"""Consequence-safe request execution — the no-blind-replay invariant.

The invariant: *a consequential call whose outcome is
unknown must not be blindly retried in a way that could duplicate a
side-effecting action.* This module classifies failures precisely so retries
happen only where they are provably safe:

  * **Pre-response failures** (the server never received the request — e.g. a
    connect timeout) are safe to retry for *any* method: the action never
    started.
  * **Idempotent methods** (``GET``/``HEAD``/``OPTIONS``/``PUT``/``DELETE``, per
    RFC 7231) are safe to retry even on an *ambiguous* failure: replaying them
    cannot duplicate an effect by definition.
  * **Ambiguous failures on a consequential method** (``POST``/``PATCH`` sent,
    but no response read — a read timeout, a mid-flight connection drop) are the
    dangerous case. Here the server may have fully processed the action, so the
    SDK does **not** retry. Instead it either
      - attaches a caller-supplied **idempotency key** the server deduplicates,
        making the replay safe, or
      - raises :class:`mudraid.MudraIDExecutionUnknownError` and hands the
        outcome-unknown decision back to the caller.

An *HTTP response* — even a 5xx — is a definite outcome and is always returned;
retrying on status codes is a separate policy the SDK intentionally leaves to
the caller. Only *transport* exceptions are classified here.
"""

from __future__ import annotations

import logging
from typing import Callable

import requests

from mudraid.exceptions import MudraIDExecutionUnknownError

_logger = logging.getLogger("mudraid.consequence")

# RFC 7231 idempotent methods: replaying them cannot duplicate an effect, so an
# ambiguous (sent, no response) failure may be safely retried.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"})

# The header the server deduplicates on. A stable key across attempts lets the
# server collapse a replayed consequential call to a single effect.
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


def is_idempotent(method: str) -> bool:
    """True if ``method`` is idempotent (safe to replay on an ambiguous failure)."""
    return method.upper() in _IDEMPOTENT_METHODS


def _is_pre_response_failure(exc: requests.RequestException) -> bool:
    """True when the request provably never reached the server.

    A connect timeout means the TCP/TLS connection was never established, so the
    server never saw the request — the action never started and a retry is safe
    for any method. Everything else that happens *after* a connection exists
    (read timeouts, mid-flight drops, chunked-encoding truncation) is treated as
    ambiguous: the bytes may already be on the server.
    """
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return True
    # A ConnectionError raised while *establishing* the connection is
    # pre-response; requests does not always distinguish, so we stay
    # conservative and treat a bare ConnectionError as ambiguous unless it is a
    # ConnectTimeout (handled above). Under-claiming "pre-response" is the safe
    # direction: at worst we refuse a retry that would have been fine.
    return False


def execute(
    send: Callable[[dict[str, str]], requests.Response],
    *,
    method: str,
    idempotency_key: str | None = None,
    max_retries: int = 1,
) -> requests.Response:
    """Run a request with consequence-safe retry semantics.

    Args:
        send: performs one attempt given the extra headers to merge in (so the
            idempotency-key header can be injected on retries). Returns the
            :class:`requests.Response`, or raises a ``requests.RequestException``
            on a transport failure.
        method: the HTTP method, used to classify idempotency.
        idempotency_key: when provided, attached as the ``Idempotency-Key``
            header on every attempt so the server can deduplicate a replay —
            which makes retrying a consequential call safe.
        max_retries: additional attempts after the first, used only where a
            retry is provably safe. Defaults to a single extra attempt.

    Returns:
        The :class:`requests.Response` from the first attempt that produced one.

    Raises:
        MudraIDExecutionUnknownError: an ambiguous failure on a consequential
            method with no idempotency key — the outcome is unknown and the SDK
            refuses to duplicate the action.
        requests.RequestException: a transport failure that exhausted the safe
            retry budget (e.g. repeated connect timeouts).
    """
    extra_headers: dict[str, str] = {}
    if idempotency_key:
        extra_headers[IDEMPOTENCY_KEY_HEADER] = idempotency_key

    method_upper = method.upper()
    # A key or an idempotent method makes a replay safe; otherwise a replay could
    # duplicate the action and is forbidden on an ambiguous failure.
    retry_is_safe = bool(idempotency_key) or is_idempotent(method_upper)

    attempt = 0
    while True:
        try:
            # A completed HTTP response — any status — is a definite outcome.
            return send(extra_headers)
        except requests.RequestException as exc:
            pre_response = _is_pre_response_failure(exc)
            can_retry = (pre_response or retry_is_safe) and attempt < max_retries
            if can_retry:
                attempt += 1
                _logger.warning(
                    "transport failure on %s (attempt %d); retry is safe "
                    "(pre_response=%s idempotent=%s keyed=%s), retrying",
                    method_upper,
                    attempt,
                    pre_response,
                    is_idempotent(method_upper),
                    bool(idempotency_key),
                    exc_info=False,
                )
                continue

            if not pre_response and not retry_is_safe:
                # The consequential + ambiguous case: sent, outcome unknown, no
                # dedupe key. Do NOT replay — surface a typed result so the
                # caller reconciles or re-issues with an idempotency key. The
                # transport error is chained; the message carries no request body.
                _logger.warning(
                    "ambiguous failure on consequential %s with no idempotency key; "
                    "NOT retrying — surfacing execution-unknown",
                    method_upper,
                )
                raise MudraIDExecutionUnknownError(
                    f"the {method_upper} request was sent but its outcome is unknown "
                    "(no response, no idempotency key). It was NOT retried to avoid "
                    "duplicating a side effect; verify server state or re-issue with an "
                    "idempotency key the server deduplicates."
                ) from exc

            # Safe-to-retry class but the retry budget is exhausted — surface the
            # original transport error unchanged.
            raise
