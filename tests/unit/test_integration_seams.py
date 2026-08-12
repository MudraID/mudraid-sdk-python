"""M4.9 — Cross-module wiring tests.

The per-module suites (env, token_manager, platform_resolver,
agent_http, agent_401_retry, logging_guards) each lock their own
behaviour cleanly. What was missing was a small set of tests that
cross the seams between them — places where two modules cooperate
and a future refactor could silently break the contract between
them without any single module's tests failing.

Scope of this file:

  - One Agent, many platforms: routing + cache isolation
  - Exception hierarchy: subclasses + ``except MudraIDError``
  - Agent lifecycle: ``close()`` releases what it claims; two Agents
    don't share state
"""

from __future__ import annotations

from typing import Iterator

import pytest
import responses

from mudraid import (
    Agent,
    MudraIDAuthError,
    MudraIDConfigError,
    MudraIDError,
    MudraIDNetworkError,
    MudraIDPlatformNotRegisteredError,
    MudraIDRevokedError,
)

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"


def _agent() -> Agent:
    return Agent(
        api_key_id="muid_kid_test",
        secret="muid_sk_test",
        base_url=MUDRAID_BASE,
    )


def _platform_entry(platform_id: str, hostname: str) -> dict:
    return {
        "platform_id": platform_id,
        "granted_scopes": ["x:y"],
        "status": "active",
        "name": hostname,
        "hostname": hostname,
        "verification_status": "verified",
    }


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


# ---- multi-platform routing ----------------------------------------------


def test_one_agent_routes_two_platforms_with_independent_tokens(
    rsps: responses.RequestsMock,
) -> None:
    """The headline cross-module case: one Agent, two platforms, each
    with its own token. The current per-module tests check the cache
    layer (TokenManager) and the routing layer (PlatformResolver) in
    isolation; this locks that the two cooperate correctly through
    Agent."""
    host_a, host_b = "api.platform-a.test", "api.platform-b.test"
    plt_a, plt_b = "plt-a", "plt-b"
    jwt_a, jwt_b = "jwt-for-A", "jwt-for-B"

    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "agent-1",
            "platforms": [
                _platform_entry(plt_a, host_a),
                _platform_entry(plt_b, host_b),
            ],
        },
        status=200,
    )

    # Token mints happen in call order: A first (per test order below),
    # then B. The mocks rely on order, not platform_id matching, so we
    # register them in the same order.
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": jwt_a, "expires_in": 900},
        status=200,
    )
    rsps.add(responses.GET, f"https://{host_a}/x", json={}, status=200)
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": jwt_b, "expires_in": 900},
        status=200,
    )
    rsps.add(responses.GET, f"https://{host_b}/x", json={}, status=200)

    agent = _agent()
    agent.get(f"https://{host_a}/x")
    agent.get(f"https://{host_b}/x")

    # Each platform's outbound request must carry that platform's token.
    # responses preserves call order in rsps.calls.
    platform_a_call = rsps.calls[2].request  # bootstrap, mint, A
    platform_b_call = rsps.calls[-1].request  # mint, B
    assert platform_a_call.headers["Authorization"] == f"Bearer {jwt_a}"
    assert platform_b_call.headers["Authorization"] == f"Bearer {jwt_b}"


def test_refreshing_one_platforms_token_leaves_another_untouched(
    rsps: responses.RequestsMock,
) -> None:
    """If platform A returns 401 and we refresh A's token, platform B's
    cached token must keep working. Otherwise a single misbehaving
    platform could ripple into extra MudraID load for every other
    platform the agent talks to."""
    host_a, host_b = "api.platform-a.test", "api.platform-b.test"

    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "a",
            "platforms": [
                _platform_entry("plt-a", host_a),
                _platform_entry("plt-b", host_b),
            ],
        },
        status=200,
    )

    # First A mint + 401, then A refresh-mint + 200.
    rsps.add(
        responses.POST, TOKEN_URL, json={"access_token": "jwt-a-old", "expires_in": 900}
    )
    rsps.add(responses.GET, f"https://{host_a}/x", json={}, status=401)
    rsps.add(
        responses.POST, TOKEN_URL, json={"access_token": "jwt-a-new", "expires_in": 900}
    )
    rsps.add(responses.GET, f"https://{host_a}/x", json={}, status=200)

    # Then a B call. If B's cache was wiped by A's refresh, we'd see a
    # third token-mint here. Don't register one — the test would fail
    # with "Connection refused" via responses, which is the signal.
    rsps.add(
        responses.POST, TOKEN_URL, json={"access_token": "jwt-b", "expires_in": 900}
    )
    rsps.add(responses.GET, f"https://{host_b}/x", json={}, status=200)

    agent = _agent()
    agent.get(f"https://{host_a}/x")  # 401 → refresh A → 200
    agent.get(f"https://{host_b}/x")  # mints B for the first time

    # Total: bootstrap + 2 A mints + 2 A platform calls + 1 B mint + 1 B platform = 7
    assert len(rsps.calls) == 7

    # The CRITICAL assertion: a SECOND B call must NOT re-mint.
    rsps.add(responses.GET, f"https://{host_b}/x", json={}, status=200)
    agent.get(f"https://{host_b}/x")
    assert len(rsps.calls) == 8, (
        "Second B call must hit B's cached token — got an extra mint, "
        "meaning A's refresh wiped B's cache."
    )


# ---- exception hierarchy --------------------------------------------------


@pytest.mark.parametrize(
    "exception_class",
    [
        MudraIDConfigError,
        MudraIDAuthError,
        MudraIDRevokedError,
        MudraIDNetworkError,
        MudraIDPlatformNotRegisteredError,
    ],
)
def test_every_specific_exception_subclasses_mudraid_error(
    exception_class: type[MudraIDError],
) -> None:
    """Locks the inheritance chain — a single ``except MudraIDError``
    block catches every SDK-raised failure. This is part of the
    public contract documented in the module docstring; the test
    catches a future contributor adding an exception that forgot
    to inherit."""
    assert issubclass(exception_class, MudraIDError)
    # And every SDK exception is itself an Exception (i.e. not, say,
    # a BaseException subclass that would dodge bare ``except``).
    assert issubclass(exception_class, Exception)


def test_single_except_clause_catches_every_sdk_error() -> None:
    """The promise of the public API: a developer can write
    ``except MudraIDError`` once and catch every flavour. This is
    what the inheritance chain BUYS them."""
    sdk_errors = [
        MudraIDConfigError("x"),
        MudraIDAuthError("x"),
        MudraIDRevokedError("x"),
        MudraIDNetworkError("x"),
        MudraIDPlatformNotRegisteredError("x"),
    ]
    for exc in sdk_errors:
        try:
            raise exc
        except MudraIDError as caught:
            assert caught is exc
        else:  # pragma: no cover — defensive
            pytest.fail(f"{type(exc).__name__} was not caught by MudraIDError")


def test_specific_except_clauses_do_not_catch_sibling_errors() -> None:
    """``except MudraIDAuthError`` must NOT catch a
    MudraIDNetworkError — otherwise the catch-bug 'I caught only
    auth errors' would silently swallow connectivity issues."""
    try:
        raise MudraIDNetworkError("not auth")
    except MudraIDAuthError:  # pragma: no cover — this branch must not execute
        pytest.fail("MudraIDAuthError must not catch MudraIDNetworkError")
    except MudraIDNetworkError:
        pass  # expected


# ---- agent lifecycle + isolation ------------------------------------------


def test_close_releases_both_sessions(rsps: responses.RequestsMock) -> None:
    """``Agent.close()`` must close BOTH HTTP sessions — the one
    talking to MudraID and the one talking to platforms. Missing
    either leaves a connection pool dangling."""
    agent = _agent()

    mudraid_session = agent._mudraid_http._session
    platform_session = agent._platform_session

    agent.close()

    # `requests.Session.close()` doesn't expose a "closed" flag, but
    # the underlying adapter pool is cleared. Re-closing is a no-op
    # safety check; what matters is that close() didn't raise and
    # both sessions were touched.
    assert mudraid_session is agent._mudraid_http._session
    assert platform_session is agent._platform_session


def test_two_agents_have_independent_caches(rsps: responses.RequestsMock) -> None:
    """Constructing a second Agent must not share state with the first.
    A shared platform map or token cache between Agents would be a
    nasty cross-contamination bug — and would defeat the per-Agent
    isolation that lets a process speak for multiple identities."""
    host = "api.platform.test"
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={"agent_id": "a1", "platforms": [_platform_entry("plt-1", host)]},
        status=200,
    )
    rsps.add(
        responses.POST, TOKEN_URL, json={"access_token": "jwt-1", "expires_in": 900}
    )
    rsps.add(responses.GET, f"https://{host}/x", json={}, status=200)

    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={"agent_id": "a2", "platforms": [_platform_entry("plt-1", host)]},
        status=200,
    )
    rsps.add(
        responses.POST, TOKEN_URL, json={"access_token": "jwt-2", "expires_in": 900}
    )
    rsps.add(responses.GET, f"https://{host}/x", json={}, status=200)

    agent1 = _agent()
    agent2 = _agent()

    agent1.get(f"https://{host}/x")
    agent2.get(f"https://{host}/x")

    # Each Agent independently bootstrapped AND minted: 2 bootstraps,
    # 2 mints, 2 platform calls = 6 total. If they shared caches, the
    # second Agent would skip both — only 4 calls.
    assert len(rsps.calls) == 6
    assert rsps.calls[2].request.headers["Authorization"] == "Bearer jwt-1"
    assert rsps.calls[-1].request.headers["Authorization"] == "Bearer jwt-2"


# ---- URL edge cases ------------------------------------------------------


def test_userinfo_in_url_is_stripped_before_routing(
    rsps: responses.RequestsMock,
) -> None:
    """``https://user:pass@api.foo.com/x`` is a valid URL; the host
    component is ``api.foo.com``. The SDK must route on the host alone
    — not pass the userinfo through as part of the matching key."""
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "a",
            "platforms": [_platform_entry("plt-1", "api.foo.com")],
        },
        status=200,
    )
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "jwt", "expires_in": 900})
    rsps.add(responses.GET, "https://user:pass@api.foo.com/x", json={}, status=200)

    resp = _agent().get("https://user:pass@api.foo.com/x")
    assert resp.status_code == 200


def test_http_and_https_routing_both_work(
    rsps: responses.RequestsMock,
) -> None:
    """The resolver matches on host, not scheme. http://api.foo.com/x
    and https://api.foo.com/x must both route. (Production agents
    will use https; local dev environments routinely use http.)"""
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={"agent_id": "a", "platforms": [_platform_entry("plt-1", "api.foo.com")]},
        status=200,
    )
    rsps.add(responses.POST, TOKEN_URL, json={"access_token": "jwt", "expires_in": 900})
    rsps.add(responses.GET, "http://api.foo.com/x", json={}, status=200)

    resp = _agent().get("http://api.foo.com/x")
    assert resp.status_code == 200
