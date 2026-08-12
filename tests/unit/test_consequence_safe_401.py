"""The legacy client must not replay a consequential 401.

THE DEFECT, STATED AS THE CUSTOMER MEETS IT. A platform mutates state and then
answers 401 — its own auth check runs late, or a proxy turns an expired session
into a 401 on the response path, or a gateway rejects after forwarding. The
legacy ``Agent`` refreshed its token and replayed the request, so the payment,
the message, the deletion happened twice; and because the second attempt
succeeded, the caller saw ``200`` with nothing indicating the first had landed.
A duplicated consequential action reported as a clean success is the worst shape
this class of bug takes.

The old defence was that a 401 proves the platform rejected the request BEFORE
processing it. That is an assertion about a server the SDK does not control and
cannot inspect, and it is false for every case above.

THE RULE NOW, which is the one :class:`mudraid.MachineAgent` already applied:
replay a 401 only when replaying provably cannot duplicate an effect —

  * an idempotent method (``GET``/``HEAD``/``OPTIONS``/``PUT``/``DELETE``), or
  * a caller-supplied ``idempotency_key`` the server deduplicates on.

Otherwise the 401 is returned unreplayed and the caller — the only party that
knows whether the action is safe to repeat — decides.

Every test asserts the number of requests that REACHED THE PLATFORM. That is the
fact a customer is billed by; a status code alone cannot distinguish "retried
safely" from "charged twice".
"""

from __future__ import annotations

import json as _json
from typing import Iterator

import pytest
import responses

from mudraid import Agent, MachineAgent, MudraIDExecutionUnknownError

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"
PLATFORM_HOST = "api.platform.test"
PLATFORM_URL = f"https://{PLATFORM_HOST}/payments"


def _agent() -> Agent:
    return Agent(api_key_id="muid_kid_test", secret="muid_sk_test", base_url=MUDRAID_BASE)


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        yield mock


def _stub_control_plane(mock: responses.RequestsMock) -> None:
    """Bootstrap + two token mints, so a refresh always has one available."""
    mock.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "platforms": [
                {
                    "platform_id": "plt-1",
                    "hostname": PLATFORM_HOST,
                    "status": "active",
                    "verification_status": "verified",
                }
            ]
        },
        status=200,
    )
    for token in ("jwt-1", "jwt-2"):
        mock.add(
            responses.POST,
            TOKEN_URL,
            json={"access_token": token, "expires_in": 900},
            status=200,
        )


def _platform_calls(mock: responses.RequestsMock) -> list:
    return [c for c in mock.calls if c.request.url.startswith(f"https://{PLATFORM_HOST}")]


# ---------------------------------------------------------------------------
# The defect itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verb, responses_verb", [("post", responses.POST), ("patch", responses.PATCH)]
)
def test_a_consequential_401_is_not_replayed_without_a_key(
    rsps: responses.RequestsMock, verb: str, responses_verb: str
) -> None:
    """The double-charge scenario.

    The platform would answer 200 on a second attempt. The assertion is that
    there is no second attempt: one request reaches the platform and the caller
    is handed the 401 to reason about.
    """
    _stub_control_plane(rsps)
    rsps.add(responses_verb, PLATFORM_URL, json={"error": "expired"}, status=401)
    # Registered but must never be reached. If the SDK replays, this answers 200
    # and the caller is told the action succeeded — while it happened twice.
    rsps.add(responses_verb, PLATFORM_URL, json={"ok": True}, status=200)

    response = getattr(_agent(), verb)(PLATFORM_URL, json={"amount": 5000})

    assert len(_platform_calls(rsps)) == 1, "the consequential request was sent twice"
    assert response.status_code == 401, "the caller must see the 401, not a laundered 200"


def test_the_unreplayed_401_is_returned_not_raised(rsps: responses.RequestsMock) -> None:
    """Refusing the replay must not become an exception.

    A 401 is a definite outcome the caller can act on. Raising would make the
    safe path harder to adopt than the unsafe one, which is how a safety default
    gets turned off.
    """
    _stub_control_plane(rsps)
    rsps.add(responses.POST, PLATFORM_URL, json={"error": "expired"}, status=401)

    response = _agent().post(PLATFORM_URL, json={"amount": 1})

    assert response.status_code == 401
    assert response.json() == {"error": "expired"}


def test_no_token_refresh_is_spent_on_a_refusal(rsps: responses.RequestsMock) -> None:
    """If we are not going to replay, there is nothing to refresh a token FOR.

    Minting one anyway would spend the per-api_key_id rate budget (which
    ``_http`` documents is shared across token, verify and bootstrap) on a call
    that never happens.
    """
    _stub_control_plane(rsps)
    rsps.add(responses.POST, PLATFORM_URL, json={}, status=401)

    _agent().post(PLATFORM_URL, json={"amount": 1})

    mints = [c for c in rsps.calls if c.request.url == TOKEN_URL]
    assert len(mints) == 1, "a second token was minted for a replay that never happened"


# ---------------------------------------------------------------------------
# What still replays, so the fix is not simply "retry less"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verb, responses_verb",
    [
        ("get", responses.GET),
        ("put", responses.PUT),
        ("delete", responses.DELETE),
        ("options", responses.OPTIONS),
    ],
)
def test_an_idempotent_401_still_replays(
    rsps: responses.RequestsMock, verb: str, responses_verb: str
) -> None:
    """Replaying these cannot duplicate an effect (RFC 7231), so the recovery
    that makes the SDK pleasant to use is untouched."""
    _stub_control_plane(rsps)
    rsps.add(responses_verb, PLATFORM_URL, json={}, status=401)
    rsps.add(responses_verb, PLATFORM_URL, json={"ok": True}, status=200)

    response = getattr(_agent(), verb)(PLATFORM_URL)

    assert len(_platform_calls(rsps)) == 2
    assert response.status_code == 200


@pytest.mark.parametrize(
    "verb, responses_verb", [("post", responses.POST), ("patch", responses.PATCH)]
)
def test_an_idempotency_key_restores_the_replay(
    rsps: responses.RequestsMock, verb: str, responses_verb: str
) -> None:
    """The key is the caller's statement that the server will collapse a
    duplicate, which is exactly what makes the replay safe."""
    _stub_control_plane(rsps)
    rsps.add(responses_verb, PLATFORM_URL, json={}, status=401)
    rsps.add(responses_verb, PLATFORM_URL, json={"ok": True}, status=200)

    response = getattr(_agent(), verb)(
        PLATFORM_URL, json={"amount": 5000}, idempotency_key="pay-001"
    )

    calls = _platform_calls(rsps)
    assert len(calls) == 2
    assert response.status_code == 200
    # On BOTH attempts: a key that only reached the replay would deduplicate
    # nothing, because the server would have no first request to match it to.
    assert [c.request.headers.get("Idempotency-Key") for c in calls] == ["pay-001", "pay-001"]
    # And the replayed body is the original one, not a stripped copy.
    assert _json.loads(calls[1].request.body) == {"amount": 5000}


def test_the_replay_carries_the_refreshed_token(rsps: responses.RequestsMock) -> None:
    """A keyed replay is still a 401 recovery — it must use the NEW token, or it
    is a guaranteed second 401 that also duplicated the action."""
    _stub_control_plane(rsps)
    rsps.add(responses.POST, PLATFORM_URL, json={}, status=401)
    rsps.add(responses.POST, PLATFORM_URL, json={"ok": True}, status=200)

    _agent().post(PLATFORM_URL, json={"a": 1}, idempotency_key="k")

    calls = _platform_calls(rsps)
    assert calls[0].request.headers["Authorization"] == "Bearer jwt-1"
    assert calls[1].request.headers["Authorization"] == "Bearer jwt-2"


# ---------------------------------------------------------------------------
# The transport half of the same rule
# ---------------------------------------------------------------------------


def test_an_ambiguous_transport_failure_on_a_consequential_call_is_not_replayed(
    rsps: responses.RequestsMock,
) -> None:
    """The 401 path is not the only way a replay can duplicate an action.

    A request that was sent with no response read is the same hazard from the
    other direction, and routing the legacy client through
    ``_consequence.execute`` closes both with one rule rather than two.
    """
    import requests

    _stub_control_plane(rsps)
    rsps.add(responses.POST, PLATFORM_URL, body=requests.exceptions.ReadTimeout("no response"))
    rsps.add(responses.POST, PLATFORM_URL, json={"ok": True}, status=200)

    with pytest.raises(MudraIDExecutionUnknownError, match="outcome is unknown"):
        _agent().post(PLATFORM_URL, json={"amount": 5000})

    assert len(_platform_calls(rsps)) == 1


def test_an_ambiguous_transport_failure_on_an_idempotent_call_is_replayed(
    rsps: responses.RequestsMock,
) -> None:
    import requests

    _stub_control_plane(rsps)
    rsps.add(responses.GET, PLATFORM_URL, body=requests.exceptions.ReadTimeout("no response"))
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    assert _agent().get(PLATFORM_URL).status_code == 200
    assert len(_platform_calls(rsps)) == 2


# ---------------------------------------------------------------------------
# The two clients must not disagree about this
# ---------------------------------------------------------------------------


def test_both_public_clients_expose_the_same_consequential_signature() -> None:
    """P1-1's remedy is that the legacy profile stops being the unsafe one.

    An integrator moving between ``Agent`` and ``MachineAgent`` should not also
    be changing retry semantics, and should not discover that the keyword that
    makes a call safe exists on only one of them.
    """
    import inspect

    for verb in ("post", "patch", "put", "delete"):
        legacy = inspect.signature(getattr(Agent, verb)).parameters
        machine = inspect.signature(getattr(MachineAgent, verb)).parameters
        assert "idempotency_key" in legacy, f"Agent.{verb} cannot be made safe"
        assert "idempotency_key" in machine, f"MachineAgent.{verb} lost its key"
        assert legacy["idempotency_key"].kind is inspect.Parameter.KEYWORD_ONLY
        assert legacy["idempotency_key"].default is None
