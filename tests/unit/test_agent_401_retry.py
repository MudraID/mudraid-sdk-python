"""Agent's 401-retry path.

Locks the contract:

  - 200 first time → no refresh, no retry.
  - 401 first → refresh JWT → replay once → return whatever comes back,
    **but only when the replay is consequence-safe** (see below).
  - 401 then 200 → return 200 (SDK quietly recovers).
  - 401 then 401 → return the second 401 (no loop).
  - 403 / 5xx → NOT retried (the SDK doesn't loop on permanent denials).
  - Retry replays with the new token, the caller's headers, and the same body.
  - Refresh failure (network / auth error from MudraID) propagates — the
    developer needs to know their credentials are broken.

CONSEQUENCE SAFETY CHANGED WHAT SOME OF THESE TESTS ASSERT, and the change is
the point rather than an accommodation. This file used to lock replay for EVERY
verb, including ``POST`` and ``PATCH``. That is the behaviour the 401 audit
identifies: a platform that mutates state and then answers 401 has the mutation
performed twice, and the caller sees a clean success from the second attempt
with nothing to indicate the first landed.

The rule is now the one :class:`mudraid.MachineAgent` already applied — replay
when replaying provably cannot duplicate an effect. Two tests moved:

  * ``test_retry_preserves_caller_headers_and_body`` keeps its subject (the
    replay carries the caller's kwargs) and supplies the idempotency key that
    makes a POST replay legal.
  * ``test_every_verb_retries_on_401`` split into the idempotent verbs, which
    still replay unconditionally, and the consequential ones, which do not.

``test_consequence_safe_401.py`` holds the new invariant directly.
"""

from __future__ import annotations

import json as _json
from typing import Iterator

import pytest
import responses

from mudraid import Agent, MudraIDAuthError, MudraIDNetworkError

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"

PLATFORM_HOST = "api.platform.test"
PLATFORM_ID = "plt-1"
PLATFORM_URL = f"https://{PLATFORM_HOST}/x"


def _agent() -> Agent:
    return Agent(
        api_key_id="muid_kid_test",
        secret="muid_sk_test",
        base_url=MUDRAID_BASE,
    )


def _stub_bootstrap(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "agent-1",
            "platforms": [
                {
                    "platform_id": PLATFORM_ID,
                    "granted_scopes": ["x:y"],
                    "status": "active",
                    "name": "P",
                    "hostname": PLATFORM_HOST,
                    "verification_status": "verified",
                }
            ],
        },
        status=200,
    )


def _stub_token(rsps: responses.RequestsMock, jwt: str) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": jwt, "token_type": "Bearer", "expires_in": 900},
        status=200,
    )


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


# ---- happy path ----------------------------------------------------------


def test_200_first_time_does_not_trigger_refresh(rsps: responses.RequestsMock) -> None:
    """Locks the zero-overhead happy path. If a future refactor accidentally
    forces a refresh on every call, every agent in production doubles its
    token-mint load on MudraID."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-1")
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    resp = _agent().get(PLATFORM_URL)

    assert resp.status_code == 200
    # 1 bootstrap + 1 mint + 1 platform = 3 total. No retry, no refresh.
    assert len(rsps.calls) == 3


# ---- 401 recovery --------------------------------------------------------


def test_401_then_200_is_silently_recovered(rsps: responses.RequestsMock) -> None:
    """The headline M4.6 case. Token mid-flight expiry / rotation
    should be invisible to the caller — they see a 200, not a 401."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={"err": "expired"}, status=401)
    _stub_token(rsps, "jwt-new")
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    resp = _agent().get(PLATFORM_URL)

    assert resp.status_code == 200
    # bootstrap + mint + plat-401 + refresh-mint + plat-200 = 5
    assert len(rsps.calls) == 5


def test_retry_uses_freshly_minted_token(rsps: responses.RequestsMock) -> None:
    """Critical: the replayed request must carry the new JWT, not the
    one that just failed. Otherwise we'd just hit the same 401 again."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-new")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=200)

    _agent().get(PLATFORM_URL)

    first_platform_call = rsps.calls[2]  # bootstrap, mint, then platform
    second_platform_call = rsps.calls[4]  # then refresh-mint, then retry
    assert first_platform_call.request.headers["Authorization"] == "Bearer jwt-old"
    assert second_platform_call.request.headers["Authorization"] == "Bearer jwt-new"


def test_retry_preserves_caller_headers_and_body(rsps: responses.RequestsMock) -> None:
    """The retry must replay the same request — headers, body, params —
    not a stripped-down version. Locks the kwargs-preservation
    refactor that powers retry.

    Uses a POST with an ``idempotency_key``: the subject here is kwargs
    preservation across the replay, and a consequential verb is the case where
    dropping a body would matter most. The key is what makes the replay legal
    at all now — without one this POST would not be retried (see
    ``test_consequence_safe_401.py``).
    """
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-1")
    rsps.add(responses.POST, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-2")
    rsps.add(responses.POST, PLATFORM_URL, json={}, status=200)

    _agent().post(
        PLATFORM_URL,
        json={"name": "thing"},
        headers={"X-Trace-Id": "abc-123"},
        idempotency_key="key-abc",
    )

    second_attempt = rsps.calls[4].request
    # Body survives — same JSON payload on the retry.
    assert _json.loads(second_attempt.body) == {"name": "thing"}
    # Caller header survives.
    assert second_attempt.headers["X-Trace-Id"] == "abc-123"
    # Authorization is the FRESH token, not the original one.
    assert second_attempt.headers["Authorization"] == "Bearer jwt-2"
    # And the key the server deduplicates on is on BOTH attempts — a key that
    # only reached the replay would deduplicate nothing.
    assert rsps.calls[2].request.headers["Idempotency-Key"] == "key-abc"
    assert second_attempt.headers["Idempotency-Key"] == "key-abc"


# ---- no-loop guarantee ---------------------------------------------------


def test_401_twice_returns_second_401_without_looping(
    rsps: responses.RequestsMock,
) -> None:
    """An agent whose permission has been revoked between the two
    attempts will see a second 401. The SDK must NOT keep refreshing
    forever — single retry only."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-new")
    rsps.add(responses.GET, PLATFORM_URL, json={"err": "still rejected"}, status=401)

    resp = _agent().get(PLATFORM_URL)

    assert resp.status_code == 401
    # bootstrap + mint + 401 + refresh-mint + 401 = 5. No third attempt.
    assert len(rsps.calls) == 5


# ---- non-401 responses do NOT retry --------------------------------------


@pytest.mark.parametrize(
    "status_code", [200, 201, 204, 400, 403, 404, 409, 500, 502, 503]
)
def test_non_401_responses_are_returned_without_retry(
    rsps: responses.RequestsMock, status_code: int
) -> None:
    """Only 401 is interpreted as 'token might be stale'. Everything
    else is the platform's answer — pass it through."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt")
    # Some statuses (204) have no body; pass an empty body explicitly.
    if status_code == 204:
        rsps.add(responses.GET, PLATFORM_URL, body="", status=status_code)
    else:
        rsps.add(responses.GET, PLATFORM_URL, json={}, status=status_code)

    resp = _agent().get(PLATFORM_URL)

    assert resp.status_code == status_code
    # bootstrap + mint + 1 platform = 3. No retry, no second mint.
    assert len(rsps.calls) == 3


# ---- refresh failure propagates -----------------------------------------


def test_refresh_failure_propagates_as_auth_error(
    rsps: responses.RequestsMock,
) -> None:
    """If MudraID rejects credentials when we try to refresh, the
    developer must hear about it — surfacing the original 401 would
    hide the actual problem (revoked or wrong-cred agent)."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    # Refresh-mint call fails with 401 (credentials no longer valid).
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )

    with pytest.raises(MudraIDAuthError):
        _agent().get(PLATFORM_URL)


def test_refresh_failure_propagates_as_network_error(
    rsps: responses.RequestsMock,
) -> None:
    """A connectivity blip during refresh must NOT be swallowed."""
    import requests as _requests

    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    rsps.add(
        responses.POST,
        TOKEN_URL,
        body=_requests.exceptions.ConnectionError("network down"),
    )

    with pytest.raises(MudraIDNetworkError):
        _agent().get(PLATFORM_URL)


# ---- every verb retries ----------------------------------------------


@pytest.mark.parametrize(
    "method_name, responses_verb",
    [
        ("get", responses.GET),
        ("put", responses.PUT),
        ("delete", responses.DELETE),
        ("options", responses.OPTIONS),
        # HEAD intentionally omitted: responses can't stub a HEAD with
        # a JSON body, and verb-specific retry behaviour is identical
        # for HEAD anyway (it routes through the same _request).
    ],
)
def test_every_idempotent_verb_retries_on_401(
    rsps: responses.RequestsMock, method_name: str, responses_verb: str
) -> None:
    """Retry behaviour must be identical for every idempotent verb. If a future
    refactor splits the request paths, this catches it.

    ``POST`` and ``PATCH`` were removed from this parametrisation deliberately:
    replaying them can duplicate an effect, so they are no longer retried
    without an idempotency key. Their behaviour is locked in
    ``test_consequence_safe_401.py`` rather than dropped.
    """
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-1")
    rsps.add(responses_verb, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-2")
    rsps.add(responses_verb, PLATFORM_URL, json={"ok": True}, status=200)

    resp = getattr(_agent(), method_name)(PLATFORM_URL)

    assert resp.status_code == 200
    assert len(rsps.calls) == 5


@pytest.mark.parametrize(
    "method_name, responses_verb",
    [("post", responses.POST), ("patch", responses.PATCH)],
)
def test_consequential_verbs_retry_on_401_when_keyed(
    rsps: responses.RequestsMock, method_name: str, responses_verb: str
) -> None:
    """The other half of the same contract: an idempotency key restores the
    replay for a consequential verb, because the server can then collapse the
    duplicate."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-1")
    rsps.add(responses_verb, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-2")
    rsps.add(responses_verb, PLATFORM_URL, json={"ok": True}, status=200)

    resp = getattr(_agent(), method_name)(PLATFORM_URL, idempotency_key="k-1")

    assert resp.status_code == 200
    assert len(rsps.calls) == 5
