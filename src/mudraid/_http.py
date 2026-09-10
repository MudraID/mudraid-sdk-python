"""Internal HTTP client for MudraID's control-plane endpoints.

This module is the *single* place inside the SDK that talks to MudraID
itself (as opposed to the platforms the agent calls). Both
:mod:`mudraid._token_manager` and :mod:`mudraid._platform_resolver`
route their HTTP traffic through here so:

  - base-URL joining is consistent
  - status-code → exception mapping is consistent (resists drift)
  - timeouts have one default
  - the underlying ``requests.Session`` is reused (connection pooling)
  - a future addition of correlation IDs / metrics / TLS pinning
    has exactly one site to touch.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from mudraid._env import SdkConfig
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDBillingFrozenError,
    MudraIDNetworkError,
    MudraIDProductionMachineClientRequiredError,
    MudraIDRateLimitedError,
    MudraIDRevokedError,
)

_logger = logging.getLogger("mudraid.http")

_DEFAULT_TIMEOUT_SEC = 10.0


def _retry_after_seconds(response: requests.Response) -> int | None:
    """Whole seconds from a ``Retry-After`` header, or ``None``.

    ``None`` means "the server did not tell us", never a guessed default: a
    caller must be able to distinguish a delay it was given from one it made
    up. Only the delta-seconds form is read — MudraID sends that — and an
    HTTP-date, a negative value or anything unparseable is treated as absent
    rather than coerced into a number that would be wrong.
    """
    raw = (response.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        seconds = int(raw)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


def _error_code(response: requests.Response) -> str | None:
    """The server's own machine-readable ``error_code``, when it sent one.

    Only identity-service's application-level refusals carry this field. A
    limiter at the edge answers with its own body shape and no ``error_code``,
    which is precisely the signal we want: absence means "not attributable",
    not "attributable to the default".
    """
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        # Two spellings, one meaning. The rate-limit and fair-use refusals
        # render `error_code`; the typed refusals raised through identity's
        # CodedHTTPException (the production credential floor among them)
        # render `code`. Both are identity describing its own decision.
        for key in ("error_code", "code"):
            code = body.get(key)
            if isinstance(code, str) and code:
                return code
    return None


# identity-service's production credential floor (KAN-171): a native agent
# credential asked to mint on a surface whose stored environment is
# production. Rendered through CodedHTTPException, so the code arrives as
# `code`, beside two guidance members.
_PRODUCTION_MACHINE_CLIENT_REQUIRED_CODE = "production_machine_client_required"


def _production_floor_guidance(
    response: requests.Response,
) -> tuple[str | None, bool | None]:
    """The two guidance members of the production refusal, read only when
    the server sent them. Absent is ``None``, never an assumed value."""
    try:
        body = response.json()
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    recommended = body.get("recommended_authentication_method")
    available = body.get("compatibility_authentication_available")
    return (
        recommended if isinstance(recommended, str) and recommended else None,
        available if isinstance(available, bool) else None,
    )


# identity-service's per-api_key_id limiter, shared by /auth/token,
# /auth/verify and the bootstrap read (see its TokenRateLimiter).
_SHARED_KEY_BUDGET_CODE = "RATE_LIMITED"
# identity-service's per-ACCOUNT plan ceiling / abuse block. A
# different limit with a different remedy: waiting may never clear it.
_ACCOUNT_FAIR_USE_CODE = "FAIR_USE_EXCEEDED"


# Kong's rate-limiting plugin sets these on every response it meters, INCLUDING
# the 429 it raises itself (verified against the plugin handler at the pinned
# image version, kong 3.9.3, not from recollection). identity-service sets none
# of them — it sends `Retry-After` and a JSON `error_code` and nothing else.
#
# `Retry-After` is deliberately NOT in this tuple even though the gateway sends
# it: so does identity-service, so its presence distinguishes nothing. Only the
# RateLimit-specific families are gateway-only.
_GATEWAY_RATE_LIMIT_HEADER_PREFIXES = ("ratelimit-", "x-ratelimit-")


def _has_gateway_rate_limit_headers(response: requests.Response) -> bool:
    """True when the gateway's own rate-limit accounting is on this response."""
    return any(
        name.lower().startswith(_GATEWAY_RATE_LIMIT_HEADER_PREFIXES) for name in response.headers
    )


def _rate_limit_attribution(response: requests.Response) -> str:
    """Which limiter refused, stated only on evidence.

    THE DEFAULT IS "WE DO NOT KNOW". An unattributed 429 gets a message saying
    so rather than one that names a limiter on no evidence.

    THE BODY OUTRANKS THE HEADERS, AND THAT PRECEDENCE IS THE WHOLE TRICK.
    Kong attaches its rate-limit headers to responses it PROXIES, not only to
    the ones it rejects — so an identity-service 429 that travelled through the
    gateway arrives carrying both a JSON `error_code` and a set of
    `X-RateLimit-*` headers. Reading the headers first would blame the gateway
    for every application-level refusal in the system.

    An `error_code` is identity-service describing its own decision, so it wins
    whenever present — INCLUDING a code this SDK does not recognise. The header
    branch is gated on its absence rather than on "neither known code matched",
    because those two differ on exactly one case: a 429 carrying a THIRD
    application code that a newer identity-service added. Matching on the known
    pair alone would let that case fall through to the headers and be blamed on
    the gateway, which is the same misattribution this precedence exists to
    prevent — arriving silently, on a service change, long after this was
    written. An unrecognised code lands on the honest "we do not know" message
    instead: it says the layer is unattributed, which is true, rather than
    naming the one layer we can rule out.

    Absence is what `_error_code` already normalises to — a missing field, a
    non-string and an empty string all return None — so `code is None` is
    exactly "the body did not describe its own decision", which is the case
    the gateway's own rejection produces: its body is Kong's, and carries no
    `error_code` at all.
    """
    code = _error_code(response)
    if code == _SHARED_KEY_BUDGET_CODE:
        return (
            " This one is the per-api_key_id budget, shared across token, "
            "verify and platform-bootstrap calls for this key — spending it on "
            "any of them spends it for all three."
        )
    if code == _ACCOUNT_FAIR_USE_CODE:
        return (
            " This one is the ACCOUNT's fair-use ceiling, not a per-key budget. "
            "Slowing this agent down may not clear it: the limit belongs to the "
            "whole account, so check the plan in the MudraID portal."
        )
    if code is None and _has_gateway_rate_limit_headers(response):
        return (
            " This one is the GATEWAY's limit, not your key's and not your "
            "account's — it is keyed by where the call came from, so anything "
            "else sharing your egress address spends it too. Your own budget "
            "may be untouched, and throttling this agent may not be the fix."
        )
    return (
        " MudraID limits these calls at more than one layer and this response "
        "did not say which one refused — it may be the per-api_key_id budget, "
        "the account's fair-use ceiling, or a gateway limit keyed by caller "
        "source and shared with everything else behind the same address. "
        "Slowing down is the first move either way."
    )


def billing_frozen_error(
    response: requests.Response, *, label: str, detail: str | None = None
) -> MudraIDBillingFrozenError:
    """The typed 402, built once for both profiles (pre-launch scan SSC-11).

    ``label`` names what was refused as it reads in the sentence — the path
    for the legacy profile, "the token request" for V2 — and ``detail`` is the
    server's own sentence when the caller already extracted one (the OAuth
    ``error_description``); otherwise the JSON ``detail`` is read here.
    """
    detail = detail or _safe_detail(response)
    if detail:
        return MudraIDBillingFrozenError(
            f"MudraID refused {label} on this account's billing state: {detail} "
            "A retry on its own cannot clear this — the freeze has to be "
            "lifted first."
        )
    # No usable body: say what the status means and where to look, and do NOT
    # name the specific state. `frozen` is the server's word for one of the
    # things that answers 402; with nothing on the wire the SDK does not get
    # to claim which.
    return MudraIDBillingFrozenError(
        f"MudraID answered 402 for {label} and sent no explanation. "
        "That status is about this account's plan and billing state, not "
        "about this request — a retry on its own cannot clear it. Check "
        "Billing in the MudraID portal."
    )


def rate_limited_error(response: requests.Response, *, label: str) -> MudraIDRateLimitedError:
    """The typed 429, built once for both profiles (pre-launch scan SSC-11).

    Carries ``Retry-After`` as a number when the server sent one, and attributes
    the limiter only on the body's own evidence (:func:`_rate_limit_attribution`).
    ``label`` reads as the object of "rate-limited" — "this request to <path>"
    for the legacy profile, "the token request" for V2.
    """
    retry_after = _retry_after_seconds(response)
    wait = (
        f" Retry after {retry_after}s."
        if retry_after is not None
        else " The server sent no Retry-After, so the length is unknown."
    )
    return MudraIDRateLimitedError(
        f"MudraID rate-limited {label}.{wait}{_rate_limit_attribution(response)}",
        retry_after_seconds=retry_after,
    )


def _safe_detail(response: requests.Response) -> str | None:
    """Best-effort extraction of the server's `detail` field.

    Errors and non-JSON bodies are swallowed — we never let detail
    extraction itself raise. Returns ``None`` when no usable detail
    is available; callers should fall back to their own default
    message.
    """
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        detail = body.get("detail") or body.get("message")
        if isinstance(detail, str) and detail:
            return detail
    return None


class MudraIDHttpClient:
    """Thin HTTP client for MudraID's own API surface.

    Not for use against the platforms the agent calls — those go
    through ``requests`` directly (with the Bearer JWT attached) in
    :mod:`mudraid._agent`.
    """

    def __init__(self, config: SdkConfig, timeout: float = _DEFAULT_TIMEOUT_SEC) -> None:
        self._config = config
        self._timeout = timeout
        # A Session lets us reuse the TCP connection across the
        # bootstrap call and the per-platform token mints — meaningful
        # latency saving on agents that talk to multiple platforms.
        self._session = requests.Session()

    @property
    def base_url(self) -> str:
        return self._config.base_url

    @property
    def api_key_id(self) -> str:
        return self._config.api_key_id

    @property
    def secret(self) -> str:
        # Module-internal. Never logged; never exposed via Agent.
        return self._config.secret

    def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON body to ``base_url + path`` and return the parsed response.

        Maps responses to SDK exceptions:

          * 2xx with valid JSON → parsed dict returned.
          * 401 → :class:`MudraIDAuthError`.
          * 402 → :class:`MudraIDBillingFrozenError`, message taken from the
            server's ``detail`` when present — the account's plan refused,
            not the request.
          * 403 → :class:`MudraIDRevokedError`, message taken from the
            server's ``detail`` when present; a 403 carrying
            ``code: production_machine_client_required`` is its subclass
            :class:`MudraIDProductionMachineClientRequiredError`, carrying
            the server's recommended authentication method.
          * Network failure / timeout / non-JSON / other non-2xx →
            :class:`MudraIDNetworkError`.

        The request body is *not* echoed into any exception message —
        it contains the agent's plaintext secret.
        """
        url = f"{self._config.base_url}{path}"
        # `path` is logged; `body` is NOT. The MudraID request body
        # contains the agent's plaintext secret — it must never appear
        # in logs, exception messages, or any other diagnostic output.
        _logger.debug("POST %s", path)
        try:
            # allow_redirects=False, and this is a credential-safety decision
            # rather than a style one.
            #
            # `requests` follows redirects by default, and on 307/308 it REPLAYS
            # the method and the body at the new location. This body carries the
            # agent's plaintext secret. `Session.rebuild_auth` strips the
            # Authorization HEADER when the host changes — it has no equivalent
            # for a body, because in general it cannot know one is sensitive.
            # So a control plane that is misconfigured, or a DNS/edge answer that
            # is hostile, could redirect this POST and receive the secret in full,
            # with `requests` doing exactly what it documents.
            #
            # There is nothing to give up by refusing: the SDK calls two fixed
            # paths that exist on every MudraID deployment and neither is
            # specified to redirect. A 3xx here is a misrouted base_url, which is
            # the 404 branch's diagnosis and gets the same treatment.
            response = self._session.post(
                url, json=body, timeout=self._timeout, allow_redirects=False
            )
        except requests.RequestException as exc:
            # Chain the underlying transport error for debuggability,
            # but keep the surfaced message generic so it never echoes
            # the request body.
            #
            # WHEN THE HOST IS THE COMPILED-IN DEFAULT, SAY SO (pre-launch scan
            # SSC-17). No single default host is right for every environment —
            # the credential screen prints the one that is — so an unconfigured
            # SDK failing to connect is a configuration fact, not the transient
            # transport fault this class otherwise describes, and the message
            # names the setting rather than leaving the reader to retry DNS.
            unconfigured = (
                (
                    " MUDRAID_BASE_URL is not set, so the SDK fell back to its "
                    "compiled-in default, which may not be the environment your "
                    "credentials belong to. Take the base URL from the credential "
                    "screen in the MudraID portal and set MUDRAID_BASE_URL (or pass "
                    "base_url= to Agent())."
                )
                if self._config.base_url_defaulted
                else ""
            )
            raise MudraIDNetworkError(
                f"could not reach MudraID at {self._config.base_url}.{unconfigured}"
            ) from exc

        _logger.debug("MudraID returned %d for %s", response.status_code, path)

        if response.status_code == 401:
            raise MudraIDAuthError("invalid credentials")
        if response.status_code == 403:
            detail = _safe_detail(response)
            if _error_code(response) == _PRODUCTION_MACHINE_CLIENT_REQUIRED_CODE:
                # THE ONE 403 WHOSE REMEDY IS NOT "CHECK YOUR GRANTS". The
                # agent is assigned and its credential was accepted; the
                # surface is production and a native credential is not a
                # production credential. The server names the way in, and
                # the SDK carries it rather than replacing it with the
                # generic grants sentence, which would send the reader to a
                # screen that cannot fix this.
                guidance = _production_floor_guidance(response)
                raise MudraIDProductionMachineClientRequiredError(
                    (detail or "MudraID refused a native agent credential on a production surface.")
                    + f" Recommended: authenticate as a linked machine client with "
                    f"{guidance[0] or 'private_key_jwt'} (mudraid.MachineAgent). A retry "
                    "with the same credential cannot succeed.",
                    recommended_authentication_method=guidance[0],
                    compatibility_authentication_available=guidance[1],
                )
            raise MudraIDRevokedError(
                detail
                or (
                    "agent not authorized for this MudraID call; check platform "
                    "grants in the MudraID portal"
                )
            )
        if response.status_code == 402:
            # THE LIMIT THE PRODUCT ACTUALLY IMPOSES, AND THE LAST CONTROL-PLANE
            # STATUS WITH NO BRANCH. Identity-service answers 402 when the
            # agent's billing_state is `frozen` — written by metering when a
            # trial lapses or a downgrade puts the account's agents over the
            # plan's ceiling. The credentials were verified before this refusal,
            # so it is not an auth failure; and it is not transient, so the
            # generic branch's `MudraIDNetworkError` was actively misleading:
            # that is the one class the published pages tell a reader to "retry
            # with backoff — it may be transient". A backoff loop against a
            # freeze never ends.
            #
            # The server sends the remedy AND the screen it lives on. The SDK is
            # the only channel the integrator has — there is no dashboard in the
            # room — so the sentence is carried through rather than replaced.
            raise billing_frozen_error(response, label=path)
        if response.status_code == 429:
            # The credentials were never examined, so this is emphatically NOT
            # an auth failure — "unexpected status 429" invited exactly that
            # misreading, which is why this branch exists.
            #
            # BUT THE SDK CANNOT KNOW WHICH LIMITER SPOKE. At least three sit on
            # these paths and only two of them are the same thing:
            #
            #   * identity-service's per-api_key_id budget    -> RATE_LIMITED
            #   * identity-service's per-ACCOUNT fair-use ceiling
            #                                                 -> FAIR_USE_EXCEEDED
            #   * Kong's service-level rate-limiting plugin on the whole
            #     identity-service block, keyed by caller source rather than by
            #     key, which answers with its own body and no error_code
            #
            # So the message leads with what is certainly true and attributes a
            # cause ONLY when the body says so itself. Naming the per-key budget
            # unconditionally would send a reader to throttle one agent when the
            # real limit was their account plan or a shared egress IP — a
            # confident wrong answer, which is worse than the vague one it
            # replaced.
            raise rate_limited_error(response, label=f"this request to {path}")
        if 300 <= response.status_code < 400:
            # Not followed (see the allow_redirects note above). Reported as its
            # own diagnosis rather than folded into "unexpected status", because
            # the cause is nearly always the same as the 404 below — a base_url
            # pointing at something that is not this agent's control plane — and
            # the remedy is the same too. The Location value is NOT echoed: it is
            # attacker-controllable in exactly the scenario this refusal exists
            # for, and printing it into a log invites someone to go and try it.
            raise MudraIDNetworkError(
                f"MudraID answered {response.status_code} (a redirect) for {path} at "
                f"{self._config.base_url}. The SDK does not follow redirects on "
                "control-plane calls — this request body carries the agent's "
                "secret, and a redirect would resend it to wherever the response "
                "pointed. That path does not redirect on a MudraID deployment, so "
                "check MUDRAID_BASE_URL: it usually means the URL resolves to a "
                "proxy, a login portal or a vanity domain rather than the API."
            )
        if response.status_code == 404:
            # THE ONE THAT COST SOMEONE TWO DAYS. A 404 from the control plane
            # is almost never "this resource does not exist" — the SDK calls
            # two fixed, always-present paths. It means the request reached
            # something that is not MudraID's control plane for this agent:
            # the wrong base_url, or an edge that does not route this path.
            #
            # The SDK KNOWS the base_url and has always logged it at DEBUG. The
            # message just never said it, so the one fact that identifies the
            # cause was one log level away from a reader who had no reason to
            # think configuration was involved.
            raise MudraIDNetworkError(
                f"MudraID returned 404 for {path} at {self._config.base_url}. "
                "That path exists on every MudraID deployment, so this usually "
                "means MUDRAID_BASE_URL points somewhere that is not MudraID's "
                "control plane for this agent — check it before the credentials. "
                "An agent also exists in exactly one environment: credentials "
                "issued by one are unknown to another."
            )
        if not 200 <= response.status_code < 300:
            raise MudraIDNetworkError(
                f"unexpected status {response.status_code} from MudraID "
                f"for {path} at {self._config.base_url}"
            )

        try:
            return response.json()
        except ValueError as exc:
            # THE 2xx TWIN OF THE 404 ABOVE, AND IT COST SOMEONE THE SAME DAY.
            # A base_url pointing at a web front end rather than the API does
            # NOT arrive here as a 404: a single-page app served from a CDN
            # rewrites unknown paths to its own index.html and answers 200. So
            # every status guard above passes, and the first thing that notices
            # is `json()` failing on a page of HTML.
            #
            # The old message named neither the URL nor what actually came
            # back, so the one reader who most needed to suspect configuration
            # was told only that the response was "non-JSON" — while its 3xx
            # and 404 siblings had already learned to say where they were
            # pointed and what that usually means. This says it too.
            #
            # The BODY IS NOT ECHOED, for the same reason the redirect branch
            # refuses to echo Location: it is attacker-controllable in exactly
            # the scenario this refusal exists for. The media type is a bounded
            # header value and is reported alone, without its parameters.
            media_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
            saw = f" It answered {media_type}." if media_type else ""
            front_end = (
                (
                    " A 200 of HTML on a control-plane path is characteristically a "
                    "web front end, not an API: single-page-app hosting serves its "
                    "index page for any unknown path, so the status says 'found' "
                    "about a file that has nothing to do with this request. Check "
                    "MUDRAID_BASE_URL — the dashboard host and the API host are "
                    "different names."
                )
                if media_type.lower() in {"text/html", "application/xhtml+xml"}
                else ""
            )
            raise MudraIDNetworkError(
                f"MudraID returned {response.status_code} for {path} at "
                f"{self._config.base_url}, but the body is not JSON."
                f"{saw}{front_end}"
            ) from exc

    def close(self) -> None:
        self._session.close()
