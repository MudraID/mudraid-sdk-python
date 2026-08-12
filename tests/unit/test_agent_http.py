"""M4.5 — Agent HTTP methods wired to PlatformResolver + TokenManager.

Each test mocks three things:

  - ``POST /api/v1/auth/agents/me/platforms`` (resolver bootstrap)
  - ``POST /api/v1/auth/token``                (token mint)
  - the upstream platform URL the developer is calling

The tests assert the *contract* — Authorization header present and
correctly shaped, all ``requests`` kwargs forwarded verbatim, error
paths surface the right SDK exception types — not the wire-level
mechanics of ``requests`` itself.
"""

from __future__ import annotations

import json as _json
from typing import Iterator

import pytest
import responses

from mudraid import Agent, MudraIDAuthError, MudraIDPlatformNotRegisteredError

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"

PLATFORM_HOST = "api.skyscanner.test"
PLATFORM_ID = "plt-skyscanner-1"
JWT_VALUE = "header.payload.signature"


def _agent() -> Agent:
    return Agent(
        api_key_id="muid_kid_test",
        secret="muid_sk_test",
        base_url=MUDRAID_BASE,
    )


def _stub_bootstrap_and_token(
    rsps: responses.RequestsMock, jwt: str = JWT_VALUE
) -> None:
    """Register the two MudraID calls the SDK makes on first use."""
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "agent-1",
            "platforms": [
                {
                    "platform_id": PLATFORM_ID,
                    "granted_scopes": ["items:read", "items:write"],
                    "status": "active",
                    "name": "Skyscanner Test",
                    "hostname": PLATFORM_HOST,
                    "verification_status": "verified",
                }
            ],
        },
        status=200,
    )
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


# ---- header injection ----------------------------------------------------


def test_get_attaches_bearer_token_from_token_manager(
    rsps: responses.RequestsMock,
) -> None:
    _stub_bootstrap_and_token(rsps)
    rsps.add(
        responses.GET, f"https://{PLATFORM_HOST}/flights", json={"ok": True}, status=200
    )

    resp = _agent().get(f"https://{PLATFORM_HOST}/flights")

    assert resp.status_code == 200
    # Identify the outbound platform request (the third call after
    # bootstrap + token mint) and inspect its Authorization header.
    platform_request = rsps.calls[-1].request
    assert platform_request.headers["Authorization"] == f"Bearer {JWT_VALUE}"


def test_caller_headers_are_preserved_and_authorization_is_overwritten(
    rsps: responses.RequestsMock,
) -> None:
    """A developer's custom headers ride along, but their own
    Authorization header (if any) is silently replaced with the SDK's
    bearer token — attaching MudraID auth is literally the SDK's
    job."""
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)

    _agent().get(
        f"https://{PLATFORM_HOST}/x",
        headers={
            "X-Trace-Id": "abc-123",
            "Authorization": "Bearer SOMETHING-ELSE",
        },
    )

    platform_request = rsps.calls[-1].request
    assert platform_request.headers["X-Trace-Id"] == "abc-123"
    assert platform_request.headers["Authorization"] == f"Bearer {JWT_VALUE}"
    assert "SOMETHING-ELSE" not in platform_request.headers["Authorization"]


def test_no_caller_headers_still_attaches_authorization(
    rsps: responses.RequestsMock,
) -> None:
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)

    _agent().get(f"https://{PLATFORM_HOST}/x")

    assert rsps.calls[-1].request.headers["Authorization"] == f"Bearer {JWT_VALUE}"


# ---- method coverage -----------------------------------------------------


def test_every_http_verb_routes_through_request_machinery(
    rsps: responses.RequestsMock,
) -> None:
    """Each verb must produce a real upstream call with the bearer
    token attached. If a future refactor accidentally short-circuits
    one of them, this catches it."""
    _stub_bootstrap_and_token(rsps)
    url = f"https://{PLATFORM_HOST}/x"
    # HEAD responses must not carry a body — every other verb is fine
    # with the canned empty-JSON.
    for verb in (
        responses.GET,
        responses.POST,
        responses.PUT,
        responses.DELETE,
        responses.PATCH,
        responses.OPTIONS,
    ):
        rsps.add(verb, url, json={}, status=200)
    rsps.add(responses.HEAD, url, body="", status=200)

    agent = _agent()
    for method_name in ("get", "post", "put", "delete", "patch", "head", "options"):
        getattr(agent, method_name)(url)

    # 2 MudraID calls (bootstrap + token) + 7 platform calls = 9 total.
    assert len(rsps.calls) == 9
    for call in rsps.calls[2:]:  # skip the two MudraID calls
        assert call.request.headers["Authorization"] == f"Bearer {JWT_VALUE}"


# ---- kwarg forwarding ----------------------------------------------------


def test_params_are_forwarded_to_requests(rsps: responses.RequestsMock) -> None:
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/search", json={}, status=200)

    _agent().get(f"https://{PLATFORM_HOST}/search", params={"q": "hello"})

    assert rsps.calls[-1].request.url.endswith("?q=hello")


def test_json_body_is_forwarded(rsps: responses.RequestsMock) -> None:
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.POST, f"https://{PLATFORM_HOST}/items", json={}, status=201)

    _agent().post(f"https://{PLATFORM_HOST}/items", json={"name": "thing"})

    body = _json.loads(rsps.calls[-1].request.body)
    assert body == {"name": "thing"}


def test_data_form_body_is_forwarded(rsps: responses.RequestsMock) -> None:
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.POST, f"https://{PLATFORM_HOST}/form", json={}, status=200)

    _agent().post(f"https://{PLATFORM_HOST}/form", data={"name": "thing"})

    body = rsps.calls[-1].request.body
    # `requests` encodes form data lazily — body may surface as bytes or
    # str depending on transport. Normalise before substring-checking.
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    assert "name=thing" in body


def test_timeout_is_forwarded_to_requests(rsps: responses.RequestsMock) -> None:
    """``responses`` doesn't expose the timeout that was passed to the
    underlying call, so we patch requests.Session.request and assert
    the kwarg was forwarded verbatim."""
    _stub_bootstrap_and_token(rsps)

    agent = _agent()
    captured: dict = {}
    original = agent._platform_session.request

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return original(*args, **kwargs)

    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)
    agent._platform_session.request = spy  # type: ignore[method-assign]

    agent.get(f"https://{PLATFORM_HOST}/x", timeout=3.5)

    assert captured.get("timeout") == 3.5


# ---- response passthrough ------------------------------------------------


def test_response_object_is_returned_unmodified(rsps: responses.RequestsMock) -> None:
    """The SDK is a thin wrapper — the caller gets a real
    ``requests.Response`` with status, headers, body all intact."""
    _stub_bootstrap_and_token(rsps)
    rsps.add(
        responses.GET,
        f"https://{PLATFORM_HOST}/x",
        json={"data": [1, 2, 3]},
        status=200,
        headers={"X-Server": "test"},
    )

    resp = _agent().get(f"https://{PLATFORM_HOST}/x")

    assert resp.status_code == 200
    assert resp.json() == {"data": [1, 2, 3]}
    assert resp.headers.get("X-Server") == "test"


def test_platform_side_4xx_response_is_returned_not_raised(
    rsps: responses.RequestsMock,
) -> None:
    """The 401-retry logic lives in M4.6. Today the SDK passes
    platform-side 4xx straight through so M4.6 can layer retry without
    changing this contract."""
    _stub_bootstrap_and_token(rsps)
    rsps.add(
        responses.GET,
        f"https://{PLATFORM_HOST}/x",
        json={"error": "bad input"},
        status=400,
    )

    resp = _agent().get(f"https://{PLATFORM_HOST}/x")
    assert resp.status_code == 400


# ---- routing failures --------------------------------------------------


def test_unknown_host_raises_before_any_network_call(
    rsps: responses.RequestsMock,
) -> None:
    """Routing must fail loudly *before* a token is minted or the
    platform is contacted — otherwise we'd leak useless JWTs to
    unregistered hosts."""
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={"agent_id": "a", "platforms": []},  # no platforms granted
        status=200,
    )

    with pytest.raises(MudraIDPlatformNotRegisteredError):
        _agent().get("https://api.unknown.test/x")

    # Exactly one call: the bootstrap. No token mint, no platform call.
    assert len(rsps.calls) == 1


def test_mint_failure_propagates_before_platform_call(
    rsps: responses.RequestsMock,
) -> None:
    """If MudraID won't mint a token, the upstream platform must NOT
    be contacted. Confirms the order of operations."""
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "a",
            "platforms": [
                {
                    "platform_id": PLATFORM_ID,
                    "granted_scopes": [],
                    "status": "active",
                    "name": "Test",
                    "hostname": PLATFORM_HOST,
                    "verification_status": "verified",
                }
            ],
        },
        status=200,
    )
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )

    with pytest.raises(MudraIDAuthError):
        _agent().get(f"https://{PLATFORM_HOST}/x")

    # bootstrap + token mint, no platform call.
    assert len(rsps.calls) == 2


# ---- caching across calls ------------------------------------------------


def test_multiple_calls_share_bootstrap_and_token_caches(
    rsps: responses.RequestsMock,
) -> None:
    """Five GETs to the same platform must do bootstrap ONCE, mint a
    token ONCE, and hit the platform five times."""
    _stub_bootstrap_and_token(rsps)
    for _ in range(5):
        rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)

    agent = _agent()
    for _ in range(5):
        agent.get(f"https://{PLATFORM_HOST}/x")

    # 1 bootstrap + 1 mint + 5 platform calls = 7 total.
    assert len(rsps.calls) == 7


# ---- refresh_platforms ---------------------------------------------------


def test_refresh_platforms_clears_both_resolver_and_token_caches(
    rsps: responses.RequestsMock,
) -> None:
    """After refresh_platforms the next call must re-bootstrap AND
    re-mint — otherwise a revoked platform could keep serving stale
    tokens from cache."""
    _stub_bootstrap_and_token(rsps, jwt="jwt-1")
    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)
    # Stubs for the post-refresh round.
    _stub_bootstrap_and_token(rsps, jwt="jwt-2")
    rsps.add(responses.GET, f"https://{PLATFORM_HOST}/x", json={}, status=200)

    agent = _agent()
    agent.get(f"https://{PLATFORM_HOST}/x")
    agent.refresh_platforms()
    resp = agent.get(f"https://{PLATFORM_HOST}/x")

    assert resp.status_code == 200
    # Second platform call carries the second token, proving the
    # token cache was flushed alongside the resolver map.
    last_request_auth = rsps.calls[-1].request.headers["Authorization"]
    assert last_request_auth == "Bearer jwt-2"


# ---- safety guarantees ---------------------------------------------------


def test_secret_never_appears_in_outbound_platform_request(
    rsps: responses.RequestsMock,
) -> None:
    """Platform-side calls must NEVER carry the agent's plaintext
    secret. The Authorization header is a JWT; the body is whatever
    the caller passed. If a refactor accidentally routes through
    the MudraID HTTP client, the secret would leak."""
    _stub_bootstrap_and_token(rsps)
    rsps.add(responses.POST, f"https://{PLATFORM_HOST}/x", json={}, status=200)

    _agent().post(f"https://{PLATFORM_HOST}/x", json={"data": "ok"})

    platform_call = rsps.calls[-1].request
    rendered = (platform_call.body or b"").decode("utf-8", errors="ignore")
    rendered += " ".join(f"{k}: {v}" for k, v in platform_call.headers.items())
    assert "muid_sk_test" not in rendered, (
        "Agent secret leaked into the outbound platform request — "
        "every platform call must carry only the JWT, never the secret."
    )
