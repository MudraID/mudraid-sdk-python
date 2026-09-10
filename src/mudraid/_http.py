"""Shared OAuth billing and rate-limit response parsing; no credential transport."""

from __future__ import annotations

import requests

from mudraid.exceptions import (
    MudraIDBillingFrozenError,
    MudraIDRateLimitedError,
)


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


# An explicit application limiter code. Do not infer its accounting key
# from the code alone; OAuth and other endpoints have different budgets.
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
            " The authorization service reported its request budget was exceeded. "
            "Use Retry-After when provided and check token-request frequency."
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
        "did not say which one refused — it may be a client request budget, "
        "the account's fair-use ceiling, or a gateway limit keyed by caller "
        "source and shared with everything else behind the same address. "
        "Slowing down is the first move either way."
    )


def billing_frozen_error(
    response: requests.Response, *, label: str, detail: str | None = None
) -> MudraIDBillingFrozenError:
    """The typed billing refusal for OAuth token requests.

    ``label`` names what was refused, and ``detail`` is the
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
    """The typed rate-limit refusal for OAuth token requests.

    Carries ``Retry-After`` as a number when the server sent one, and attributes
    the limiter only on the body's own evidence (:func:`_rate_limit_attribution`).
    ``label`` identifies the refused request.
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
