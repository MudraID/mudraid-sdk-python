"""The legacy profile stays reachable and covered.

The V2 upgrade is additive: the legacy api_key_id/secret profile — including its
historical behaviour that an empty ``scopes`` request expands to the agent's
*full* permitted set — must keep working unchanged, now selectable explicitly via
:meth:`Agent.legacy`. These regression tests lock that so the V2 work does not
silently alter or remove the legacy path.

Note the deliberate contrast with the V2 invariant: here an empty scope IS the
full-authority default (legacy semantics, preserved). That broadening lives ONLY
behind the explicitly-named legacy profile; the V2 :class:`mudraid.MachineAgent`
never does it.
"""

from __future__ import annotations

import json as _json
from typing import Iterator

import pytest
import responses

from mudraid import Agent

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"
PLATFORM_HOST = "api.platform.test"
PLATFORM_ID = "plt-1"
PLATFORM_URL = f"https://{PLATFORM_HOST}/x"


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


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


def _stub_token(rsps: responses.RequestsMock, jwt: str = "jwt-legacy") -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": jwt, "token_type": "Bearer", "expires_in": 900},
        status=200,
    )


def test_legacy_constructor_is_equivalent_and_functional(
    rsps: responses.RequestsMock,
) -> None:
    """Agent.legacy(...) constructs the legacy profile and performs a full flow
    (bootstrap → mint → platform call) exactly as the default constructor does."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-legacy")
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    agent = Agent.legacy(api_key_id="muid_kid_test", secret="muid_sk_test", base_url=MUDRAID_BASE)
    assert isinstance(agent, Agent)
    assert agent.api_key_id == "muid_kid_test"

    resp = agent.get(PLATFORM_URL)
    assert resp.status_code == 200
    # bootstrap + mint + platform = 3
    assert len(rsps.calls) == 3


def test_legacy_empty_scopes_request_full_authority_default_preserved(
    rsps: responses.RequestsMock,
) -> None:
    """Regression lock on the LEGACY semantics: the token-mint body carries
    ``scopes: []`` — which the backend expands to the agent's full permitted
    set. This is the historical behaviour and must stay intact behind the legacy
    profile (contrast V2, where an omitted scope is the minimal set)."""
    _stub_bootstrap(rsps)
    _stub_token(rsps)
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    Agent.legacy(api_key_id="muid_kid_test", secret="muid_sk_test", base_url=MUDRAID_BASE).get(
        PLATFORM_URL
    )

    mint_call = next(c for c in rsps.calls if c.request.url == TOKEN_URL)
    body = _json.loads(mint_call.request.body)
    assert body["scopes"] == [], "legacy profile must keep sending empty scopes (full-authority)"
    assert body["api_key_id"] == "muid_kid_test"
    assert body["platform_id"] == PLATFORM_ID


def test_legacy_401_retry_behaviour_unchanged(rsps: responses.RequestsMock) -> None:
    """The legacy 401 refresh-and-replay path is unchanged by the V2 work."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, "jwt-old")
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, "jwt-new")
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    resp = Agent.legacy(
        api_key_id="muid_kid_test", secret="muid_sk_test", base_url=MUDRAID_BASE
    ).get(PLATFORM_URL)
    assert resp.status_code == 200
    assert len(rsps.calls) == 5
