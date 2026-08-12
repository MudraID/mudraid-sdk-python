"""URL host → platform_id resolution.

The SDK bootstraps once at first use by calling
``POST /api/v1/auth/agents/me/platforms`` (backend tasks M0.6 + M0.6b).
Each entry in the response carries a verified hostname; we build a
``hostname → platform_id`` map and use it for the rest of the SDK
lifetime to route ``agent.get("https://api.skyscanner.com/...")`` to
the right platform's JWT.

Locked behaviour (don't drift on these without an explicit decision):

  - Bootstrap is **lazy**: the first ``resolve()`` triggers the HTTP
    call, not the ``Agent()`` constructor. Tests and short-lived
    scripts that never make a call therefore never touch the
    network.
  - The bootstrap is **double-checked-locked**: under thread contention
    only one HTTP request goes out; the late-arrivers re-read the
    cached map. Validated by ``test_concurrent_first_resolve_…``.
  - Routing is **strict**: revoked, unverified, or hostname-less
    entries are silently dropped from the map. Better a clear
    "platform not registered" error than silently routing to a
    platform with stale verification.
  - The lookup is **case-insensitive on host** but otherwise an exact
    match — no wildcards, no subdomain glob. ``api.skyscanner.com``
    routes; ``api2.skyscanner.com`` does not. Wildcards are a v1.x
    feature once we have telemetry on what people actually need.
  - Refresh is **explicit**: callers (or the Agent) invoke
    :py:meth:`refresh` when the agent's platform grant set changes
    in the portal. We don't poll; the steady state is cache-warm.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
from urllib.parse import urlsplit

from mudraid._http import MudraIDHttpClient
from mudraid.exceptions import MudraIDPlatformNotRegisteredError

_logger = logging.getLogger("mudraid.platform_resolver")

_PLATFORMS_ENDPOINT = "/api/v1/auth/agents/me/platforms"


class PlatformResolver:
    """Lazy-bootstrapped URL-host → platform_id resolver."""

    def __init__(self, http_client: MudraIDHttpClient) -> None:
        self._http = http_client
        self._lock = threading.Lock()
        # None == not yet bootstrapped. Empty dict == bootstrapped but
        # no usable entries (every entry was revoked, unverified, or
        # missing a hostname). The two states behave the same for
        # callers — both produce MudraIDPlatformNotRegisteredError on
        # resolve — but only the None state triggers a bootstrap.
        self._map: dict[str, str] | None = None

    def resolve(self, url: str) -> str:
        """Return the platform_id whose verified hostname matches ``url``.

        The first call triggers a bootstrap fetch; subsequent calls
        read the in-memory map. The HTTP call happens inside the lock
        so concurrent first calls under threading do not stampede the
        MudraID endpoint.

        Raises:
            MudraIDPlatformNotRegisteredError: if the URL has no host,
                or the host is not in the agent's registered+verified
                platform set.
        """
        host = self._extract_host(url)
        mapping = self._ensure_loaded()
        platform_id = mapping.get(host)
        if platform_id is None:
            raise MudraIDPlatformNotRegisteredError(
                f"Host '{host}' is not in this agent's registered platforms. "
                "Grant the platform to the agent in the MudraID portal and "
                "call Agent.refresh_platforms() (or recreate the Agent)."
            )
        return platform_id

    def refresh(self) -> None:
        """Discard the cached map; the next ``resolve()`` re-bootstraps.

        Callers should invoke this after granting a new platform to
        the agent in the portal. There is no automatic polling — the
        cache is treated as authoritative until refreshed.
        """
        _logger.info("platform map refresh requested")
        with self._lock:
            self._map = None

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> dict[str, str]:
        # Fast-path read without the lock: by the time the SDK has been
        # used once, every subsequent resolve must be lock-free for
        # latency. Reading a dict reference is atomic in CPython, so
        # `is not None` is a safe signal that the map is fully built.
        if self._map is not None:
            return self._map
        with self._lock:
            # Re-check inside the lock: another thread may have
            # populated the map while we were waiting for it.
            if self._map is not None:
                return self._map
            _logger.info("bootstrapping platform map from MudraID")
            response = self._http.post_json(
                _PLATFORMS_ENDPOINT,
                {
                    "api_key_id": self._http.api_key_id,
                    "secret": self._http.secret,
                },
            )
            self._map = self._build_map(response.get("platforms") or [])
            # Map keys and values (hostnames + platform_ids) are both
            # public/non-sensitive — safe to surface at DEBUG for
            # diagnosing "why doesn't my URL route?" cases.
            _logger.info("platform map ready: %d routable hosts", len(self._map))
            _logger.debug("routable hosts: %s", sorted(self._map.keys()))
            return self._map

    @staticmethod
    def _build_map(platforms: list[dict[str, Any]]) -> dict[str, str]:
        """Filter the bootstrap response down to routable entries.

        Drops anything that would be unsafe or impossible to route to:

          - ``status != "active"`` (the agent's permission was revoked
            on this platform; routing would mint a token we couldn't
            use anyway)
          - Missing or null ``hostname`` (the M0.6b enrichment was
            unavailable; without a hostname there is nothing to match)
          - ``verification_status != "verified"`` (the platform's
            domain verification has lapsed; routing risks sending a
            valid JWT to an attacker who stood up a look-alike host)
          - Missing ``platform_id`` (defensive against a malformed
            backend response)
        """
        mapping: dict[str, str] = {}
        for entry in platforms:
            if entry.get("status") != "active":
                continue
            hostname = entry.get("hostname")
            if not isinstance(hostname, str) or not hostname.strip():
                continue
            if entry.get("verification_status") != "verified":
                continue
            platform_id = entry.get("platform_id")
            if not isinstance(platform_id, str) or not platform_id:
                continue
            # Lower-case for case-insensitive match. First-wins on the
            # rare duplicate (the bootstrap response shouldn't contain
            # two entries for the same hostname; if it does, we don't
            # want to spook the developer with a hard error).
            mapping.setdefault(hostname.strip().lower(), platform_id)
        return mapping

    @staticmethod
    def _extract_host(url: str) -> str:
        """Pull a routable hostname out of ``url``.

        ``urlsplit().hostname`` already strips the port and
        lowercases the host (per RFC 3986), so the result is
        directly comparable to our map keys.
        """
        host = urlsplit(url).hostname
        if not host:
            raise MudraIDPlatformNotRegisteredError(
                f"URL '{url}' has no host; pass an absolute URL like "
                "https://api.example.com/...",
            )
        return host
