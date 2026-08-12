"""Per-platform JWT cache + refresh.

A single ``TokenManager`` instance is owned by each :class:`mudraid.Agent`.
Its job:

  1. On request: return a non-expired JWT for the given ``platform_id``.
  2. Mint a fresh JWT via ``POST /api/v1/auth/token`` when there is no
     cached token, when the cached token is near expiry, or when
     :meth:`refresh` is invoked explicitly (used by the 401-retry path
     landing in M4.6).
  3. Hold the cache in process memory only — never log JWT contents,
     never persist them, never expose them through public attributes.

Locked design notes:

- The cache is a single dict + a single ``threading.Lock``. A per-key
  lock would let concurrent mints for *different* platforms proceed in
  parallel but adds complexity that v1 traffic doesn't justify.
- Expiry is tracked by the wall-clock timestamp returned implicitly by
  the backend (``expires_in`` seconds added to ``time.time()`` at mint).
  We do NOT decode the JWT — the SDK is intentionally JWT-blind so a
  future signature-algorithm change in MudraID doesn't require a SDK
  release.
- The refresh-skew (default 30 s) is a deliberate over-correction:
  it triggers a refresh *before* expiry so a long-running request will
  not race the 15-minute boundary. Clock skew between the SDK host and
  MudraID's signer also lives inside this margin.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from mudraid._http import MudraIDHttpClient
from mudraid.exceptions import MudraIDNetworkError

_logger = logging.getLogger("mudraid.token_manager")

_TOKEN_ENDPOINT = "/api/v1/auth/token"  # nosec B105 - URL path, not a credential
_REFRESH_SKEW_SEC = 30.0
# Used ONLY if the endpoint omits ``expires_in`` — deliberately short so a
# missing field never yields a long-lived cached token. This read 900 and called
# it "the locked backend default"; the backend default moved to 300 on
# 2026-08-12 (KAN-41) and is now env-tunable, so a fallback tracking it would be
# a second, unsynchronised copy of a number the server sends on every mint.
#
# THE ASYMMETRY IS THE POINT, and it is why this is not simply "keep it in step":
# guessing SHORT costs one early refresh, while guessing LONG hands out a token
# that is already dead and produces 401s with no refresh due. 900 was the unsafe
# direction. Matches ``_machine_auth._FALLBACK_EXPIRES_IN_SEC``, which had this
# right already.
_FALLBACK_EXPIRES_IN_SEC = 300


@dataclass(frozen=True)
class _CachedToken:
    access_token: str
    # Wall-clock seconds (``time.time()``) at which the token is no
    # longer considered usable. We refresh ``_REFRESH_SKEW_SEC`` before
    # this value rather than waiting for an actual expiry.
    expires_at: float

    def is_fresh(self, now: float, skew: float = _REFRESH_SKEW_SEC) -> bool:
        return now + skew < self.expires_at


class TokenManager:
    """JWT cache + refresh for one agent across many platforms."""

    def __init__(self, http_client: MudraIDHttpClient) -> None:
        self._http = http_client
        # platform_id -> _CachedToken
        self._cache: dict[str, _CachedToken] = {}
        self._lock = threading.Lock()

    def get_token(self, platform_id: str) -> str:
        """Return a non-expired JWT for ``platform_id``, minting one if needed.

        Concurrent callers for the same platform are coalesced: only
        one HTTP request to ``/auth/token`` is in flight at a time per
        platform, even under heavy threading.
        """
        now = time.time()

        # Fast path under the lock: cache hit + fresh? return immediately.
        with self._lock:
            cached = self._cache.get(platform_id)
            if cached is not None and cached.is_fresh(now):
                _logger.debug("token cache hit for platform_id=%s", platform_id)
                return cached.access_token

        # Slow path: mint outside the lock so the HTTP call doesn't
        # block other platforms, then re-acquire to publish the new
        # token. The re-check inside the lock handles the race where
        # another thread already populated the entry while we were on
        # the network.
        minted = self._mint(platform_id)
        with self._lock:
            existing = self._cache.get(platform_id)
            if existing is not None and existing.is_fresh(time.time()):
                # Another thread won the race; prefer its token to
                # avoid pinning the cache to a token we know is older
                # than what's already there.
                return existing.access_token
            self._cache[platform_id] = minted
            return minted.access_token

    def refresh(self, platform_id: str) -> str:
        """Force a fresh mint regardless of cache state.

        Called by the agent's 401-retry path (M4.6): when a platform
        rejects our token, we discard it and ask MudraID for a new one
        without trusting whatever happens to be cached.
        """
        _logger.info("refreshing token for platform_id=%s", platform_id)
        minted = self._mint(platform_id)
        with self._lock:
            self._cache[platform_id] = minted
        return minted.access_token

    def clear(self, platform_id: str | None = None) -> None:
        """Drop cached tokens. ``None`` clears everything."""
        with self._lock:
            if platform_id is None:
                _logger.debug("clearing all cached tokens")
                self._cache.clear()
            else:
                _logger.debug("clearing cached token for platform_id=%s", platform_id)
                self._cache.pop(platform_id, None)

    # ------------------------------------------------------------------

    def _mint(self, platform_id: str) -> _CachedToken:
        """Call MudraID and return a fresh ``_CachedToken``.

        Empty ``scopes`` are sent explicitly: the backend expands an
        empty request to the agent's full permitted scope set on the
        platform (this is the M2.8 default — without it MudraID would
        mint a zero-authority JWT). Sub-scoping per request is a future
        feature; for v1 the SDK always asks for everything the agent
        is allowed.
        """
        # The payload contains the agent's plaintext secret. It is
        # built and dispatched here and is never logged: MudraIDHttpClient
        # only logs the path, never the body.
        _logger.info("minting token for platform_id=%s", platform_id)
        payload = {
            "api_key_id": self._http.api_key_id,
            "secret": self._http.secret,
            "platform_id": platform_id,
            "scopes": [],
        }
        response = self._http.post_json(_TOKEN_ENDPOINT, payload)

        access_token = response.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise MudraIDNetworkError("MudraID /auth/token response missing access_token")
        expires_in = response.get("expires_in", _FALLBACK_EXPIRES_IN_SEC)
        if not isinstance(expires_in, (int, float)) or expires_in <= 0:
            expires_in = _FALLBACK_EXPIRES_IN_SEC

        return _CachedToken(
            access_token=access_token,
            expires_at=time.time() + float(expires_in),
        )
