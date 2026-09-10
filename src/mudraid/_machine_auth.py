"""V2 machine-authority auth — ``private_key_jwt`` against ``POST /oauth2/token``.

This is the newer way an agent obtains authority. Where the
legacy profile posts a plaintext ``secret`` to ``/api/v1/auth/token`` and lets an
empty ``scopes`` list expand to the agent's *full* permitted set, the V2 profile:

  * authenticates with a **``private_key_jwt`` client assertion** — a short-lived
    JWT the client signs with its own private key, so no long-lived shared secret
    ever crosses the wire (RFC 7523);
  * names an **explicit audience** (the assertion's ``aud`` — the token
    endpoint's own identifier, per doc 02 §8) and an explicit **resource**
    indicator (RFC 8707) the issued token is bound to;
  * requests **explicit scopes**, and — crucially — sends *no* ``scope`` field
    when none were named, so an omission is the empty (minimal) set and can never
    broaden to "everything" (see :mod:`mudraid._scopes`).

Signing is pluggable through :class:`AssertionSigner` so the SDK core carries no
crypto dependency: an integrator supplies a signer (the optional ``[v2]`` extra
ships :class:`PyJWTSigner`, and tests inject a fake). The manager itself is
JWT-blind about the *access* token it receives — it trusts the endpoint's
``expires_in`` and never decodes the token, mirroring the legacy TokenManager.

Secret-safety: the signed assertion and the issued access token are credentials.
They are never logged, never placed in an exception message, and never exposed
through a public attribute — only the endpoint URL and non-secret request
metadata appear in diagnostics.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import requests

from mudraid._http import billing_frozen_error, rate_limited_error
from mudraid._scopes import RequestedScopes
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDNetworkError,
    MudraIDRevokedError,
)

_logger = logging.getLogger("mudraid.machine_auth")

_JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_GRANT_CLIENT_CREDENTIALS = "client_credentials"

# Refresh a cached access token this many seconds *before* its stated expiry.
# Same rationale as the legacy TokenManager: a long request must not race the
# expiry boundary, and host/signer clock skew lives inside this margin.
_REFRESH_SKEW_SEC = 30.0
# Assertions are single-use, near-instant proofs; a tight lifetime shrinks the
# replay window. 60 s comfortably covers request latency + modest clock skew.
_DEFAULT_ASSERTION_TTL_SEC = 60
_DEFAULT_TIMEOUT_SEC = 10.0
# Only used if the endpoint omits ``expires_in`` — deliberately short so a
# missing field never yields a long-lived cached token.
_FALLBACK_EXPIRES_IN_SEC = 300


class AssertionSigner(Protocol):
    """Signs a client-assertion claim set into a compact JWS string.

    The SDK builds the *claims* (``iss``/``sub``/``aud``/``exp``/``iat``/``jti``)
    and hands them here; the signer owns the algorithm, the key, and the ``kid``
    header. Keeping this a Protocol means the SDK core never imports a crypto
    library — callers plug in :class:`PyJWTSigner` or their own KMS-backed
    implementation. Implementations must never log the key or the returned JWT.
    """

    def sign(self, claims: Mapping[str, Any]) -> str:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class MachineIdentity:
    """Everything needed to mint V2 machine-authority tokens for one client.

    Attributes:
        client_id: the machine client's identifier; becomes both ``iss`` and
            ``sub`` of every client assertion (RFC 7523 §3).
        token_endpoint: absolute URL of ``POST /oauth2/token``.
        audience: the exact identifier the assertion names in ``aud`` — the token
            endpoint's own identifier. Explicit and required: an assertion with
            the wrong (or a wildcard) audience is refused by the server, so the
            SDK forces the caller to state it rather than guessing.
        resource: the RFC 8707 resource indicator the issued token is bound to
            (its ``aud``). Explicit and required for a protected-action token.
        scopes: the explicitly requested scopes. Defaults to the empty
            (minimal) set — never a wildcard (see :class:`RequestedScopes`).
        signer: the :class:`AssertionSigner` that signs each assertion.
        assertion_ttl_seconds: lifetime stamped into each assertion's ``exp``.
    """

    client_id: str
    token_endpoint: str
    audience: str
    resource: str
    signer: AssertionSigner
    scopes: RequestedScopes = RequestedScopes.of(None)
    assertion_ttl_seconds: int = _DEFAULT_ASSERTION_TTL_SEC

    def __post_init__(self) -> None:
        # Fail fast and loudly on a misconfigured identity — every field below
        # is load-bearing for a correctly-scoped, correctly-targeted token, and
        # an empty audience/resource is exactly the kind of silent broadening
        # this story exists to prevent.
        for name in ("client_id", "token_endpoint", "audience", "resource"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"MachineIdentity.{name} is required and must be non-empty")
        if self.assertion_ttl_seconds <= 0:
            raise ValueError("assertion_ttl_seconds must be positive")


def build_client_assertion_claims(
    identity: MachineIdentity, *, now: float | None = None
) -> dict[str, Any]:
    """Build the RFC 7523 client-assertion claim set for ``identity``.

    ``iss`` and ``sub`` are both the ``client_id``; ``aud`` is the explicit
    audience; a fresh random ``jti`` makes each assertion single-use; ``exp`` is
    ``iat + assertion_ttl_seconds``. Pure and deterministic given ``now`` (except
    the random ``jti``) so it is directly unit-testable without signing.
    """
    issued_at = int(now if now is not None else time.time())
    return {
        "iss": identity.client_id,
        "sub": identity.client_id,
        "aud": identity.audience,
        "iat": issued_at,
        "exp": issued_at + identity.assertion_ttl_seconds,
        "jti": uuid.uuid4().hex,
    }


@dataclass(frozen=True)
class _MachineToken:
    access_token: str
    expires_at: float
    # The scope string the server actually granted (may be narrower than
    # requested). Non-secret; useful for diagnostics.
    granted_scope: str | None

    def is_fresh(self, now: float, skew: float = _REFRESH_SKEW_SEC) -> bool:
        return now + skew < self.expires_at


class MachineTokenManager:
    """Acquire / cache / refresh one machine client's V2 access token.

    Lifecycle mirrors the legacy TokenManager — cache until near-expiry (with a
    clock-skew leeway), re-acquire on expiry, and force a fresh mint on
    :meth:`refresh` (used by the 401 path so a revoked/expired token triggers a
    genuine re-acquire rather than silent reuse). One identity → one cached
    token; a distinct resource/scope needs a distinct identity + manager.
    """

    def __init__(
        self,
        identity: MachineIdentity,
        *,
        session: requests.Session | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self._identity = identity
        self._timeout = timeout
        # A dedicated session for the token endpoint, distinct from the session
        # that carries the issued bearer to resource servers — the two have
        # different trust properties and must never share headers.
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._cached: _MachineToken | None = None

    @property
    def identity(self) -> MachineIdentity:
        return self._identity

    def get_token(self) -> str:
        """Return a non-expired access token, acquiring one if needed."""
        now = time.time()
        with self._lock:
            cached = self._cached
            if cached is not None and cached.is_fresh(now):
                _logger.debug("machine token cache hit for client_id=%s", self._identity.client_id)
                return cached.access_token

        minted = self._acquire()
        with self._lock:
            existing = self._cached
            if existing is not None and existing.is_fresh(time.time()):
                return existing.access_token
            self._cached = minted
            return minted.access_token

    def refresh(self) -> str:
        """Discard any cached token and acquire a fresh one unconditionally.

        Called when a resource server rejects the current token (401): we do not
        trust whatever is cached, we re-acquire. A revoked/expired credential
        surfaces here as a typed error rather than being silently reused.
        """
        _logger.info("refreshing machine token for client_id=%s", self._identity.client_id)
        minted = self._acquire()
        with self._lock:
            self._cached = minted
        return minted.access_token

    def clear(self) -> None:
        """Drop the cached token; the next :meth:`get_token` re-acquires."""
        with self._lock:
            self._cached = None

    # ------------------------------------------------------------------

    def _acquire(self) -> _MachineToken:
        """Sign a fresh assertion and exchange it at the token endpoint."""
        _logger.info(
            "acquiring V2 machine token for client_id=%s resource=%s",
            self._identity.client_id,
            self._identity.resource,
        )
        claims = build_client_assertion_claims(self._identity)
        assertion = self._identity.signer.sign(claims)
        if not isinstance(assertion, str) or not assertion:
            raise MudraIDNetworkError("assertion signer returned an empty client assertion")

        # RFC 6749 form body. ``scope`` is included ONLY when scopes were
        # explicitly named — an empty request omits the field entirely so it is
        # read as least privilege, never as a request for full entitlement.
        form: dict[str, str] = {
            "grant_type": _GRANT_CLIENT_CREDENTIALS,
            "client_assertion_type": _JWT_BEARER_ASSERTION_TYPE,
            "client_assertion": assertion,
            "resource": self._identity.resource,
        }
        scope_param = self._identity.scopes.as_scope_param()
        if scope_param is not None:
            form["scope"] = scope_param

        # `data=` sends application/x-www-form-urlencoded. The body carries the
        # signed assertion — a credential — and is NEVER logged.
        _logger.debug(
            "POST %s (client_credentials, private_key_jwt)", self._identity.token_endpoint
        )
        try:
            # allow_redirects=False: this body carries the signed client
            # assertion. The assertion's own ``aud`` binds it to the intended
            # token endpoint, so a redirected copy is not directly usable — but
            # "not directly usable" is a property of the server that receives it,
            # and handing a live credential to an unintended one to find out is
            # not a check. A token endpoint does not redirect; a 3xx here is a
            # misconfigured ``token_endpoint``.
            response = self._session.post(
                self._identity.token_endpoint,
                data=form,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise MudraIDNetworkError(
                f"could not reach the token endpoint at {self._identity.token_endpoint}"
            ) from exc

        return self._parse_token_response(response)

    def _parse_token_response(self, response: requests.Response) -> _MachineToken:
        """Map a token-endpoint response to a cached token or a typed error.

        The endpoint speaks OAuth error objects (``{"error", "error_description"}``);
        we map the registered codes to the SDK's exception hierarchy without ever
        echoing the request body:

          * 401 ``invalid_client`` → :class:`MudraIDAuthError`.
          * 400 ``invalid_scope`` / ``invalid_target`` / ``invalid_request`` /
            ``unsupported_grant_type`` → :class:`MudraIDRevokedError` (an
            authority/protocol refusal, carrying the server's description).
          * 402 → :class:`MudraIDBillingFrozenError`; 429 →
            :class:`MudraIDRateLimitedError` with ``retry_after_seconds`` — the
            SAME typed errors the legacy profile raises, built by the shared
            helpers in :mod:`mudraid._http`, so a billing freeze is never read
            as the "retry with backoff" transport error (pre-launch scan
            SSC-11).
          * anything else / non-JSON / transport → :class:`MudraIDNetworkError`.
        """
        status = response.status_code
        if status == 401:
            raise MudraIDAuthError("client authentication failed at the token endpoint")
        if status == 402:
            # The OAuth body carries its sentence as error_description rather
            # than detail; hand it through so the remedy the server named is
            # the one the integrator reads.
            _, description = _safe_oauth_error(response)
            raise billing_frozen_error(response, label="the token request", detail=description)
        if status == 429:
            raise rate_limited_error(response, label="the token request")
        if 300 <= status < 400:
            raise MudraIDNetworkError(
                f"the token endpoint at {self._identity.token_endpoint} answered "
                f"{status} (a redirect). The SDK does not follow redirects when "
                "presenting a signed client assertion; check that token_endpoint "
                "names the authorization server's token endpoint directly."
            )
        if not 200 <= status < 300:
            error, description = _safe_oauth_error(response)
            if status == 400 and error:
                raise MudraIDRevokedError(
                    description or f"token request refused ({error})"
                )
            raise MudraIDNetworkError(f"unexpected status {status} from the token endpoint")

        try:
            body = response.json()
        except ValueError as exc:
            raise MudraIDNetworkError("token endpoint returned a non-JSON response") from exc
        if not isinstance(body, dict):
            raise MudraIDNetworkError("token endpoint returned an unexpected JSON shape")

        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise MudraIDNetworkError("token endpoint response missing access_token")
        # RFC 6749 §5.1 makes ``token_type`` REQUIRED, and it decides how the
        # credential must be presented. Everything downstream sends this value as
        # ``Authorization: Bearer``, so a token that is not a bearer token would
        # be presented wrongly — and a ``mac``/``dpop`` token presented as a plain
        # bearer is a credential used outside the binding that protects it.
        # Absence is tolerated (the field is widely omitted in practice and
        # bearer is the only type this SDK has ever received); a value that is
        # present and is NOT bearer is refused rather than reinterpreted.
        token_type = body.get("token_type")
        if token_type is not None and (
            not isinstance(token_type, str) or token_type.lower() != "bearer"
        ):
            raise MudraIDNetworkError(
                f"token endpoint issued a {token_type!r} token; this SDK presents "
                "credentials as 'Bearer' and will not present another type as one"
            )
        expires_in = body.get("expires_in", _FALLBACK_EXPIRES_IN_SEC)
        if not isinstance(expires_in, (int, float)) or expires_in <= 0:
            expires_in = _FALLBACK_EXPIRES_IN_SEC
        granted_scope = body.get("scope")
        if not isinstance(granted_scope, str):
            granted_scope = None

        return _MachineToken(
            access_token=access_token,
            expires_at=time.time() + float(expires_in),
            granted_scope=granted_scope,
        )


def _safe_oauth_error(response: requests.Response) -> tuple[str | None, str | None]:
    """Best-effort ``(error, error_description)`` from an OAuth error body.

    Never raises; a non-JSON or unexpected body yields ``(None, None)`` so the
    caller falls back to a generic message. The values are server-authored OAuth
    codes/descriptions — safe to surface (they never contain our request body).
    """
    try:
        body = response.json()
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    error = body.get("error")
    description = body.get("error_description")
    return (
        error if isinstance(error, str) and error else None,
        description if isinstance(description, str) and description else None,
    )


#: Signing algorithms :class:`PyJWTSigner` will use for a client assertion.
#:
#: ASYMMETRIC ONLY, AND THAT IS THE POINT OF THE PROFILE. ``private_key_jwt``
#: (RFC 7523) exists so no long-lived shared secret crosses the wire: the client
#: holds a private key, the server holds only the public half, and a server
#: compromise cannot mint assertions. Two things defeat that, and PyJWT accepts
#: both without complaint:
#:
#:   * ``none`` — an UNSIGNED assertion. PyJWT will encode one; whether it is
#:     rejected then depends entirely on the verifier, and the SDK should not be
#:     the component that finds out.
#:   * ``HS*`` — a SYMMETRIC MAC. The "private key" becomes a shared secret the
#:     server must also hold, quietly turning the profile back into the thing it
#:     replaced, with no visible change at the call site.
#:
#: Neither is a configuration this SDK has a reason to allow, so neither is
#: reachable. An integrator who needs something else supplies their own
#: :class:`AssertionSigner`, where the choice is theirs and is visible.
#:
#: EXACTLY THE TWO THE SERVER VERIFIES, AND NOT ONE MORE (KAN-171). This set
#: used to list eleven asymmetric algorithms -- every RS*, PS*, ES* and EdDSA
#: PyJWT can encode -- and the server verifies precisely two of them: RS256
#: (RSASSA-PKCS1-v1_5/SHA-256) and ES256 (ECDSA P-256/SHA-256, raw ``r||s``).
#: Key registration accepts the same two. So nine of the eleven were a promise
#: this SDK could not keep: a client configured with ``PS384`` would sign a
#: perfectly well-formed assertion and be refused with the uniform
#: ``invalid_client``, an error that -- by design -- does not say why. The
#: client library is the one place that can refuse EARLY and say why, and an
#: "asymmetric-only" rule that admits algorithms the far end cannot check is
#: not a security property, it is a list.
#:
#: This is the CLIENT'S advertised set. Widening it is not an SDK change; it
#: is a server change (verifier, key registration, metadata, contract and
#: tests together), after which this constant follows.
_PERMITTED_ASSERTION_ALGORITHMS = frozenset({"RS256", "ES256"})

#: The asymmetric algorithms PyJWT can encode that the server does NOT verify.
#: Named so the refusal can say "asymmetric, but not supported here" rather
#: than lumping a reasonable ES384 choice in with ``none`` -- the two mistakes
#: deserve different sentences, because they call for different fixes.
_UNSUPPORTED_ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS384", "RS512", "PS256", "PS384", "PS512", "ES384", "ES512", "ES256K", "EdDSA"}
)


class PyJWTSigner:
    """An :class:`AssertionSigner` backed by PyJWT (optional ``[v2]`` extra).

    Signs each claim set with the client's private key and stamps the ``kid`` so
    the server can select the matching registered public key. PyJWT is imported
    lazily so the SDK core keeps zero crypto dependencies; a missing PyJWT raises
    a clear, actionable error rather than an obscure ``ImportError`` at call
    time. The private key is held only on this instance and is never logged.

    ``algorithm`` is restricted to :data:`_PERMITTED_ASSERTION_ALGORITHMS` —
    asymmetric signatures only. See that constant for why.
    """

    def __init__(self, private_key: Any, *, kid: str, algorithm: str = "RS256") -> None:
        if not kid or not isinstance(kid, str):
            raise ValueError("kid is required so the server can select the verifying key")
        if algorithm in _UNSUPPORTED_ASYMMETRIC_ALGORITHMS:
            # Asymmetric and well-formed, so worth a different sentence from
            # the one below: the far end would refuse this with a uniform
            # invalid_client that says nothing, and this is the only place
            # that can say it early.
            raise ValueError(
                f"{algorithm!r} is not a permitted client-assertion algorithm. "
                "It is asymmetric, but MudraID verifies exactly RS256 and ES256, "
                "and an assertion signed with anything else is refused at the "
                "token endpoint with a uniform invalid_client. Choose one of "
                f"{sorted(_PERMITTED_ASSERTION_ALGORITHMS)}."
            )
        if algorithm not in _PERMITTED_ASSERTION_ALGORITHMS:
            raise ValueError(
                f"{algorithm!r} is not a permitted client-assertion algorithm. "
                "private_key_jwt is an asymmetric profile: 'none' would send an "
                "unsigned assertion and 'HS*' would make the private key a shared "
                "secret the server must also hold. Choose one of "
                f"{sorted(_PERMITTED_ASSERTION_ALGORITHMS)}, or supply your own "
                "AssertionSigner if you genuinely need something else."
            )
        self._private_key = private_key
        self._kid = kid
        self._algorithm = algorithm

    def sign(self, claims: Mapping[str, Any]) -> str:
        try:
            import jwt  # noqa: PLC0415 - lazy so the core has no crypto dep
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise MudraIDNetworkError(
                "PyJWTSigner requires PyJWT; install the SDK's 'v2' extra "
                "(pip install mudraid-sdk[v2]) or supply your own AssertionSigner"
            ) from exc
        return jwt.encode(
            dict(claims),
            self._private_key,
            algorithm=self._algorithm,
            headers={"kid": self._kid},
        )
