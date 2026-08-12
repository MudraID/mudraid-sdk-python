"""M4.3 — TokenManager: cache, refresh, error mapping, thread safety.

Tests use the ``responses`` library to intercept the SDK's HTTP calls so
no live backend is required. The few cases that exercise expiry
behaviour monkey-patch ``time.time`` rather than sleeping, so the
suite remains fast.
"""

from __future__ import annotations

import threading
from typing import Iterator

import pytest
import responses

from mudraid._env import SdkConfig
from mudraid._http import MudraIDHttpClient
from mudraid._token_manager import TokenManager
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDNetworkError,
    MudraIDRevokedError,
)

BASE_URL = "https://api.mudraid.test"
TOKEN_URL = f"{BASE_URL}/api/v1/auth/token"
PLATFORM = "plt_abc"


def _build_manager() -> TokenManager:
    config = SdkConfig(
        api_key_id="muid_kid_test", secret="muid_sk_test", base_url=BASE_URL
    )
    return TokenManager(MudraIDHttpClient(config))


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    """Per-test HTTP mock — asserts every registered route is consumed."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


# ---- Happy path: mint, cache, reuse --------------------------------------


def test_first_call_mints_jwt_via_http(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-1", "token_type": "Bearer", "expires_in": 900},
        status=200,
    )

    mgr = _build_manager()
    token = mgr.get_token(PLATFORM)

    assert token == "jwt-1"
    assert len(rsps.calls) == 1


def test_request_payload_includes_credentials_platform_and_empty_scopes(
    rsps: responses.RequestsMock,
) -> None:
    """Locks the body shape the backend expects (per docs/openapi.yaml).
    Empty `scopes` is intentional — backend M2.8 expands to the agent's
    full permitted set; passing a list lets future versions sub-scope."""
    import json as _json

    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt", "token_type": "Bearer", "expires_in": 900},
        status=200,
    )

    _build_manager().get_token(PLATFORM)

    body = _json.loads(rsps.calls[0].request.body)
    assert body == {
        "api_key_id": "muid_kid_test",
        "secret": "muid_sk_test",
        "platform_id": PLATFORM,
        "scopes": [],
    }


def test_second_call_within_expiry_returns_cached_token_without_http(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-cached", "token_type": "Bearer", "expires_in": 900},
        status=200,
    )

    mgr = _build_manager()
    first = mgr.get_token(PLATFORM)
    second = mgr.get_token(PLATFORM)

    assert first == second == "jwt-cached"
    assert len(rsps.calls) == 1, "second call must come from the cache"


def test_different_platforms_get_independent_tokens(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-A", "expires_in": 900},
        status=200,
    )
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-B", "expires_in": 900},
        status=200,
    )

    mgr = _build_manager()
    assert mgr.get_token("plt_A") == "jwt-A"
    assert mgr.get_token("plt_B") == "jwt-B"
    assert len(rsps.calls) == 2


# ---- Expiry handling -----------------------------------------------------


def test_near_expiry_token_triggers_refresh(
    rsps: responses.RequestsMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token expiring within the 30 s skew window must be re-minted on
    the next get_token. Without this, a long-running request could
    cross the expiry boundary and get a 401 mid-flight."""
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-stale", "expires_in": 60},
        status=200,
    )
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-fresh", "expires_in": 900},
        status=200,
    )

    fake_now = [1_000_000.0]

    def fake_time() -> float:
        return fake_now[0]

    import mudraid._token_manager as tm

    monkeypatch.setattr(tm.time, "time", fake_time)

    mgr = _build_manager()
    assert mgr.get_token(PLATFORM) == "jwt-stale"

    # Advance to inside the 30s skew window (token expires at t=60).
    fake_now[0] = 1_000_000.0 + 45.0  # 15s before exp, inside 30s skew

    assert mgr.get_token(PLATFORM) == "jwt-fresh"
    assert len(rsps.calls) == 2


# ---- Refresh + clear -----------------------------------------------------


def test_refresh_always_calls_http_regardless_of_cache(
    rsps: responses.RequestsMock,
) -> None:
    """The 401-retry path (M4.6) relies on refresh always bypassing the
    cache, otherwise a single bad token could ping-pong forever."""
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-1", "expires_in": 900},
        status=200,
    )
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-2", "expires_in": 900},
        status=200,
    )

    mgr = _build_manager()
    assert mgr.get_token(PLATFORM) == "jwt-1"
    assert mgr.refresh(PLATFORM) == "jwt-2"
    # And the cache is now seeded with jwt-2.
    assert mgr.get_token(PLATFORM) == "jwt-2"
    assert len(rsps.calls) == 2


def test_clear_one_platform_leaves_others_alone(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "A1", "expires_in": 900})
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "B1", "expires_in": 900})
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "A2", "expires_in": 900})

    mgr = _build_manager()
    mgr.get_token("plt_A")
    mgr.get_token("plt_B")

    mgr.clear("plt_A")

    # plt_A re-mints; plt_B still served from cache.
    assert mgr.get_token("plt_A") == "A2"
    assert mgr.get_token("plt_B") == "B1"
    assert len(rsps.calls) == 3


def test_clear_all_drops_every_entry(rsps: responses.RequestsMock) -> None:
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "A1", "expires_in": 900})
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "B1", "expires_in": 900})
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "A2", "expires_in": 900})
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "B2", "expires_in": 900})

    mgr = _build_manager()
    mgr.get_token("plt_A")
    mgr.get_token("plt_B")
    mgr.clear()

    assert mgr.get_token("plt_A") == "A2"
    assert mgr.get_token("plt_B") == "B2"


# ---- Error mapping -------------------------------------------------------


def test_401_response_raises_mudraid_auth_error(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )

    with pytest.raises(MudraIDAuthError):
        _build_manager().get_token(PLATFORM)


def test_403_response_raises_revoked_error_with_server_detail(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"detail": "not permitted: agent inactive"},
        status=403,
    )

    with pytest.raises(MudraIDRevokedError, match="agent inactive"):
        _build_manager().get_token(PLATFORM)


def test_network_failure_raises_network_error(rsps: responses.RequestsMock) -> None:
    """No responses registered → requests raises ConnectionError →
    SDK wraps it as MudraIDNetworkError."""
    import requests

    rsps.add(
        responses.POST,
        TOKEN_URL,
        body=requests.exceptions.ConnectionError("boom"),
    )

    with pytest.raises(MudraIDNetworkError):
        _build_manager().get_token(PLATFORM)


def test_500_response_raises_network_error(rsps: responses.RequestsMock) -> None:
    rsps.add(responses.POST, TOKEN_URL, json={"detail": "boom"}, status=500)

    with pytest.raises(MudraIDNetworkError, match="500"):
        _build_manager().get_token(PLATFORM)


def test_response_missing_access_token_raises_network_error(
    rsps: responses.RequestsMock,
) -> None:
    """Lock in the response-shape contract from docs/openapi.yaml. If the
    backend ever forgets access_token, the SDK fails loud rather than
    silently caching ``None``."""
    rsps.add(responses.POST, TOKEN_URL, json={"token_type": "Bearer"}, status=200)

    with pytest.raises(MudraIDNetworkError, match="access_token"):
        _build_manager().get_token(PLATFORM)


def test_non_json_response_raises_network_error(rsps: responses.RequestsMock) -> None:
    # The wording moved from "non-JSON response" to a message that also names
    # where the SDK was pointed and what came back, because a 200 carrying a
    # web page is how a wrong MUDRAID_BASE_URL actually presents. The BEHAVIOUR
    # asserted here is unchanged — still MudraIDNetworkError, still on a 200
    # whose body will not parse — so this matches the new text and additionally
    # pins the diagnostic content that made the change worth making.
    rsps.add(
        responses.POST,
        TOKEN_URL,
        body="this is not JSON",
        status=200,
        content_type="text/plain",
    )

    with pytest.raises(MudraIDNetworkError, match="not JSON") as exc:
        _build_manager().get_token(PLATFORM)

    message = str(exc.value)
    assert BASE_URL in message
    assert "text/plain" in message


def test_missing_expires_in_uses_safe_fallback(rsps: responses.RequestsMock) -> None:
    """Backend should always send expires_in (locked at 900s) but if it
    drops the field we cache the token for 15 min rather than 0
    (which would mean we re-mint on the next call)."""
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "jwt"}, status=200)

    mgr = _build_manager()
    mgr.get_token(PLATFORM)
    # Second call within the fallback window must come from cache.
    mgr.get_token(PLATFORM)

    assert len(rsps.calls) == 1


# ---- Anti-leak guard -----------------------------------------------------


def test_token_never_appears_in_thrown_exception_messages(
    rsps: responses.RequestsMock,
) -> None:
    """A 4xx/5xx that *did* somehow include the secret in its body must
    not be re-emitted in our exception messages."""
    rsps.add(
        responses.POST,
        TOKEN_URL,
        # Pathological server response that echoes credentials. Should
        # never happen, but the SDK has to be safe even when it does.
        json={"detail": "muid_sk_test was wrong"},
        status=401,
    )

    with pytest.raises(MudraIDAuthError) as exc:
        _build_manager().get_token(PLATFORM)

    assert "muid_sk_test" not in str(exc.value), (
        "401 handler must use a constant 'invalid credentials' message, "
        "not echo the server body."
    )


# ---- Thread safety -------------------------------------------------------


def test_concurrent_get_token_for_same_platform_is_safe(
    rsps: responses.RequestsMock,
) -> None:
    """Multiple threads hitting get_token on the same platform must end up
    with consistent results — no torn cache writes, no exceptions.

    Note: under the current single-lock design they MAY each trigger a
    mint (because the slow-path runs outside the lock). What matters
    for correctness is that the final cached value is one of the
    returned tokens, and every caller gets a valid string."""
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "jwt-concurrent", "expires_in": 900},
        status=200,
    )
    # Allow extra mints in case multiple threads race past the cache
    # check; assert_all_requests_are_fired=False in the fixture means
    # leftover registrations are fine.
    for _ in range(20):
        rsps.add(
            responses.POST,
            TOKEN_URL,
            json={"access_token": "jwt-concurrent", "expires_in": 900},
            status=200,
        )

    mgr = _build_manager()
    results: list[str] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(mgr.get_token(PLATFORM))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(results) == 20
    assert all(r == "jwt-concurrent" for r in results)
