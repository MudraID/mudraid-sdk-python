"""V2 machine-authority auth: private_key_jwt + token lifecycle.

Covers:
  * the client-assertion claim set (iss = sub = client_id, explicit aud, exp);
  * the form body sent to POST /oauth2/token, including the empty-scope-never-all
    invariant on the wire (no ``scope`` field when none were requested);
  * token lifecycle — acquire, cache, near-expiry refresh with clock skew,
    forced refresh, revoked/expired ⇒ re-acquire;
  * OAuth error → SDK exception mapping;
  * secret-safety: the signed assertion and the access token never leak into
    logs or exception messages.

Signing is faked so the suite needs no crypto: a fake signer records the claims
it was handed and returns a sentinel assertion string.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator, Mapping
from urllib.parse import parse_qs

import pytest
import responses

from mudraid import (
    MachineIdentity,
    MachineTokenManager,
    RequestedScopes,
    build_client_assertion_claims,
)
from mudraid._machine_auth import _JWT_BEARER_ASSERTION_TYPE
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDNetworkError,
    MudraIDRevokedError,
)

TOKEN_ENDPOINT = "https://identity.mudraid.test/oauth2/token"
AUDIENCE = "https://identity.mudraid.test/oauth2/token"
RESOURCE = "https://api.acme.test/"
CLIENT_ID = "mc_client_abc"
_ASSERTION_SENTINEL = "SIGNED.ASSERTION.CANARY-zzz"


class _FakeSigner:
    """Records the claims it signs; returns a fixed sentinel assertion."""

    def __init__(self, assertion: str = _ASSERTION_SENTINEL) -> None:
        self.assertion = assertion
        self.seen_claims: list[Mapping[str, Any]] = []

    def sign(self, claims: Mapping[str, Any]) -> str:
        self.seen_claims.append(dict(claims))
        return self.assertion


def _identity(
    *, scopes: RequestedScopes | None = None, signer: _FakeSigner | None = None
) -> MachineIdentity:
    return MachineIdentity(
        client_id=CLIENT_ID,
        token_endpoint=TOKEN_ENDPOINT,
        audience=AUDIENCE,
        resource=RESOURCE,
        signer=signer or _FakeSigner(),
        scopes=scopes if scopes is not None else RequestedScopes.of(["payments:write"]),
    )


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


def _stub_token(
    rsps: responses.RequestsMock,
    *,
    access_token: str = "at-1",
    expires_in: int = 300,
    scope: str | None = "payments:write",
) -> None:
    body: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    if scope is not None:
        body["scope"] = scope
    rsps.add(responses.POST, TOKEN_ENDPOINT, json=body, status=200)


def _form(rsps: responses.RequestsMock, idx: int = 0) -> dict[str, list[str]]:
    return parse_qs(rsps.calls[idx].request.body)


# ---- client-assertion claims ---------------------------------------------


def test_client_assertion_claims_bind_iss_sub_and_audience() -> None:
    identity = _identity()
    claims = build_client_assertion_claims(identity, now=1_000_000.0)
    # RFC 7523: the client authenticates AS itself — iss and sub are the client.
    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID
    # Explicit, exact audience — never a wildcard, never inferred.
    assert claims["aud"] == AUDIENCE
    assert claims["iat"] == 1_000_000
    assert claims["exp"] == 1_000_000 + identity.assertion_ttl_seconds
    assert claims["exp"] > claims["iat"]
    # A unique jti makes each assertion single-use (replay-resistant).
    assert claims["jti"]


def test_two_assertions_get_distinct_jti() -> None:
    identity = _identity()
    a = build_client_assertion_claims(identity)
    b = build_client_assertion_claims(identity)
    assert a["jti"] != b["jti"]


# ---- the form body / wire contract ---------------------------------------


def test_token_request_is_private_key_jwt_client_credentials(
    rsps: responses.RequestsMock,
) -> None:
    signer = _FakeSigner()
    _stub_token(rsps)
    MachineTokenManager(_identity(signer=signer)).get_token()

    form = _form(rsps)
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_assertion_type"] == [_JWT_BEARER_ASSERTION_TYPE]
    assert form["client_assertion"] == [_ASSERTION_SENTINEL]
    assert form["resource"] == [RESOURCE]
    assert form["scope"] == ["payments:write"]
    # The signer was handed the correct, explicit claims.
    assert signer.seen_claims[0]["aud"] == AUDIENCE
    assert signer.seen_claims[0]["iss"] == CLIENT_ID


def test_empty_scopes_omit_the_scope_field_entirely(
    rsps: responses.RequestsMock,
) -> None:
    """Invariant #1 on the wire: an omitted scope set sends NO ``scope`` field —
    never a wildcard, never a broadening default. The server reads the absence as
    least privilege."""
    _stub_token(rsps, scope=None)
    MachineTokenManager(_identity(scopes=RequestedScopes.of(None))).get_token()

    form = _form(rsps)
    assert "scope" not in form, "empty scopes must omit the scope field, not send a wildcard"
    # And the rest of the request is still well-formed.
    assert form["grant_type"] == ["client_credentials"]
    assert form["resource"] == [RESOURCE]


# ---- lifecycle: acquire / cache / refresh / skew -------------------------


def test_first_call_acquires_and_second_call_is_cached(
    rsps: responses.RequestsMock,
) -> None:
    _stub_token(rsps, access_token="at-cached", expires_in=300)
    mgr = MachineTokenManager(_identity())
    assert mgr.get_token() == "at-cached"
    assert mgr.get_token() == "at-cached"
    assert len(rsps.calls) == 1, "second call must be served from cache"


def test_near_expiry_token_is_re_acquired_within_skew(
    rsps: responses.RequestsMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token inside the 30 s skew window must be re-acquired on the next
    get_token, so a long request never races the expiry boundary."""
    _stub_token(rsps, access_token="at-stale", expires_in=60)
    _stub_token(rsps, access_token="at-fresh", expires_in=300)

    fake_now = [2_000_000.0]
    import mudraid._machine_auth as ma

    monkeypatch.setattr(ma.time, "time", lambda: fake_now[0])

    mgr = MachineTokenManager(_identity())
    assert mgr.get_token() == "at-stale"

    # Advance to 15 s before expiry (token expires at now+60) — inside 30 s skew.
    fake_now[0] = 2_000_000.0 + 45.0
    assert mgr.get_token() == "at-fresh"
    assert len(rsps.calls) == 2


def test_refresh_forces_reacquire_and_reseeds_cache(
    rsps: responses.RequestsMock,
) -> None:
    """A revoked/expired token at the resource server triggers refresh(): it
    must bypass the cache and re-acquire, then serve the new token."""
    _stub_token(rsps, access_token="at-1", expires_in=300)
    _stub_token(rsps, access_token="at-2", expires_in=300)

    mgr = MachineTokenManager(_identity())
    assert mgr.get_token() == "at-1"
    assert mgr.refresh() == "at-2"
    assert mgr.get_token() == "at-2"  # cache now holds at-2
    assert len(rsps.calls) == 2


def test_clear_forces_reacquire(rsps: responses.RequestsMock) -> None:
    _stub_token(rsps, access_token="at-1")
    _stub_token(rsps, access_token="at-2")
    mgr = MachineTokenManager(_identity())
    assert mgr.get_token() == "at-1"
    mgr.clear()
    assert mgr.get_token() == "at-2"
    assert len(rsps.calls) == 2


def test_missing_expires_in_uses_short_fallback_not_zero(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": "at", "token_type": "Bearer"},
        status=200,
    )
    mgr = MachineTokenManager(_identity())
    mgr.get_token()
    mgr.get_token()  # within the fallback window → cached, no second call
    assert len(rsps.calls) == 1


# ---- OAuth error mapping -------------------------------------------------


def test_invalid_client_401_maps_to_auth_error(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"error": "invalid_client", "error_description": "Client authentication failed"},
        status=401,
    )
    with pytest.raises(MudraIDAuthError):
        MachineTokenManager(_identity()).get_token()


@pytest.mark.parametrize("oauth_error", ["invalid_scope", "invalid_target", "invalid_request"])
def test_400_oauth_errors_map_to_revoked_error(
    rsps: responses.RequestsMock, oauth_error: str
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"error": oauth_error, "error_description": f"refused: {oauth_error}"},
        status=400,
    )
    with pytest.raises(MudraIDRevokedError, match=oauth_error):
        MachineTokenManager(_identity()).get_token()


def test_500_maps_to_network_error(rsps: responses.RequestsMock) -> None:
    rsps.add(responses.POST, TOKEN_ENDPOINT, json={"error": "server_error"}, status=500)
    with pytest.raises(MudraIDNetworkError, match="500"):
        MachineTokenManager(_identity()).get_token()


def test_transport_failure_maps_to_network_error(rsps: responses.RequestsMock) -> None:
    import requests

    rsps.add(responses.POST, TOKEN_ENDPOINT, body=requests.exceptions.ConnectionError("boom"))
    with pytest.raises(MudraIDNetworkError):
        MachineTokenManager(_identity()).get_token()


def test_missing_access_token_maps_to_network_error(rsps: responses.RequestsMock) -> None:
    rsps.add(responses.POST, TOKEN_ENDPOINT, json={"token_type": "Bearer"}, status=200)
    with pytest.raises(MudraIDNetworkError, match="access_token"):
        MachineTokenManager(_identity()).get_token()


def test_non_json_maps_to_network_error(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        body="not json",
        status=200,
        content_type="text/plain",
    )
    with pytest.raises(MudraIDNetworkError, match="non-JSON"):
        MachineTokenManager(_identity()).get_token()


# ---- config validation ---------------------------------------------------


@pytest.mark.parametrize("field", ["client_id", "token_endpoint", "audience", "resource"])
def test_identity_requires_non_empty_core_fields(field: str) -> None:
    kwargs: dict[str, Any] = dict(
        client_id=CLIENT_ID,
        token_endpoint=TOKEN_ENDPOINT,
        audience=AUDIENCE,
        resource=RESOURCE,
        signer=_FakeSigner(),
    )
    kwargs[field] = "   "
    with pytest.raises(ValueError, match=field):
        MachineIdentity(**kwargs)


# ---- secret-safety -------------------------------------------------------


def test_assertion_and_access_token_never_logged(
    rsps: responses.RequestsMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="mudraid")
    _stub_token(rsps, access_token="AT-LEAK-CANARY-xyz")
    MachineTokenManager(_identity()).get_token()

    blob = "\n".join(
        r.getMessage() + " " + " ".join(str(a) for a in (r.args or ()))
        for r in caplog.records
    )
    assert _ASSERTION_SENTINEL not in blob, "signed client assertion leaked into logs"
    assert "AT-LEAK-CANARY-xyz" not in blob, "access token leaked into logs"


def test_401_exception_message_does_not_echo_assertion(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"error": "invalid_client", "error_description": _ASSERTION_SENTINEL},
        status=401,
    )
    with pytest.raises(MudraIDAuthError) as exc:
        MachineTokenManager(_identity()).get_token()
    # 401 uses a constant message, never the server body / assertion.
    assert _ASSERTION_SENTINEL not in str(exc.value)


# ---- the plan's refusals are typed, as in the legacy profile ------------


def test_429_with_retry_after_maps_to_the_typed_rate_limit_error(
    rsps: responses.RequestsMock,
) -> None:
    """Pre-launch scan SSC-11 — a rate-limited token request raises the same
    MudraIDRateLimitedError the legacy profile raises, carrying Retry-After,
    rather than the generic 'unexpected status 429' transport error."""
    from mudraid.exceptions import MudraIDRateLimitedError

    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"error_code": "RATE_LIMITED", "detail": "slow down"},
        status=429,
        headers={"Retry-After": "17"},
    )
    with pytest.raises(MudraIDRateLimitedError) as exc:
        MachineTokenManager(_identity()).get_token()
    assert exc.value.retry_after_seconds == 17
    assert "Retry after 17s" in str(exc.value)
    assert "authorization service" in str(exc.value)
    assert "platform-bootstrap" not in str(exc.value)
    assert "unexpected status" not in str(exc.value)


def test_429_without_retry_after_reports_an_unknown_wait(
    rsps: responses.RequestsMock,
) -> None:
    """Pre-launch scan SSC-11 — absence is an absence, never a guessed number."""
    from mudraid.exceptions import MudraIDRateLimitedError

    rsps.add(responses.POST, TOKEN_ENDPOINT, json={"error": "slow_down"}, status=429)
    with pytest.raises(MudraIDRateLimitedError) as exc:
        MachineTokenManager(_identity()).get_token()
    assert exc.value.retry_after_seconds is None
    assert "no Retry-After" in str(exc.value)


def test_402_maps_to_the_typed_billing_frozen_error(rsps: responses.RequestsMock) -> None:
    """Pre-launch scan SSC-11 — a billing refusal is not transient; it must
    not be raised as the class the docs say to retry with backoff."""
    from mudraid.exceptions import MudraIDBillingFrozenError

    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={
            "error": "invalid_client",
            "error_description": "This account is frozen; see Billing in the portal.",
        },
        status=402,
    )
    with pytest.raises(MudraIDBillingFrozenError) as exc:
        MachineTokenManager(_identity()).get_token()
    assert "This account is frozen" in str(exc.value)
    assert "cannot clear" in str(exc.value)


def test_402_with_no_body_still_maps_to_billing_frozen(rsps: responses.RequestsMock) -> None:
    from mudraid.exceptions import MudraIDBillingFrozenError

    rsps.add(responses.POST, TOKEN_ENDPOINT, body="", status=402)
    with pytest.raises(MudraIDBillingFrozenError, match="sent no explanation"):
        MachineTokenManager(_identity()).get_token()
