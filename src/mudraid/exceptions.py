"""SDK error hierarchy.

This file declares only the base `MudraIDError`. Specific subclasses
(`MudraIDAuthError`, `MudraIDRevokedError`, `MudraIDNetworkError`,
`MudraIDPlatformNotRegisteredError`, `MudraIDConfigError`) are added
in task M4.7 once the modules that raise them exist.

All SDK-raised exceptions must inherit from `MudraIDError` so callers
can write a single `except MudraIDError:` block that catches anything
the SDK throws on its own behalf.
"""

from __future__ import annotations


class MudraIDError(Exception):
    """Base class for every error raised by the MudraID SDK.

    Catching this base exception will catch every SDK-originated
    failure — credential, network, authorisation, configuration —
    without also catching the underlying `requests` errors that the
    SDK transparently surfaces from upstream platform calls.
    """


class MudraIDConfigError(MudraIDError):
    """Configuration error — missing or invalid SDK initialisation state.

    Raised at :class:`mudraid.Agent` construction when
    ``MUDRAID_API_KEY_ID`` or ``MUDRAID_SECRET`` cannot be resolved
    from explicit arguments, the OS environment, or a ``.env`` file.
    The message lists the missing variables so recovery is one step
    away.
    """


class MudraIDAuthError(MudraIDError):
    """MudraID rejected the SDK's credentials.

    Raised when the control-plane returns HTTP 401 — typically caused
    by a wrong ``MUDRAID_API_KEY_ID`` or ``MUDRAID_SECRET``. The error
    shape is intentionally generic; MudraID itself does not reveal
    whether the api_key_id is unknown or the secret is wrong, to
    resist enumeration.
    """


class MudraIDRevokedError(MudraIDError):
    """MudraID accepted the credentials but refused the operation.

    Raised on HTTP 403 from the control-plane. Covers agent
    revocation, missing platform permission, missing/invalid scopes,
    and similar authorisation denials. The exception message echoes
    the server's ``detail`` field so the caller can distinguish — but
    callers should not parse the message; catch the exception and
    surface it to the developer.

    Future versions may split this into more specific subclasses;
    callers that catch ``MudraIDRevokedError`` today will still catch
    those subclasses tomorrow.
    """


class MudraIDNetworkError(MudraIDError):
    """SDK could not reach or could not parse a response from MudraID.

    Raised on connection errors, timeouts, unexpected non-2xx
    statuses, and malformed JSON responses. The original exception
    (if any) is chained via ``__cause__`` so detailed diagnostics
    survive without leaking into the user-facing message.
    """


class MudraIDScopeError(MudraIDError):
    """The caller asked the SDK to request authority it must never request.

    Raised **client-side, before any network call**, by the V2 machine-authority
    path when a requested scope set would broaden authority rather than name a
    specific, bounded capability — most importantly a wildcard / "all" scope.

    This is the structural half of the story's first safety invariant: an
    *omitted* scope set is the empty (minimal) set and travels as no ``scope`` at
    all, while an *explicit* wildcard is refused here rather than being forwarded.
    There is deliberately no SDK API that turns "no scopes" into "every scope";
    the only way to obtain authority is to name each scope, and naming a wildcard
    is an error, not a shortcut.
    """


class MudraIDExecutionUnknownError(MudraIDError):
    """A consequential call was sent but its outcome is unknown — do NOT replay.

    Raised by the V2 consequence-safe request path when a request that may have
    side effects (a non-idempotent method, e.g. ``POST``/``PATCH``, carrying no
    server-dedupable idempotency key) fails *after* the bytes were put on the
    wire but *before* a response was read — a read timeout, a dropped
    connection mid-flight, a truncated response. In that window the server may
    have fully processed the action, so a blind retry could duplicate it.

    This is the second safety invariant made concrete: rather than silently
    replaying and risking a double-charge / double-send, the SDK surfaces this
    typed result and hands the decision back to the caller. The caller can then
    either check server-side state and reconcile, or re-issue the call with an
    idempotency key the server deduplicates (see
    :class:`mudraid.MachineAgent`). The triggering transport error is chained via
    ``__cause__`` for diagnostics; the message never echoes the request body.
    """


class MudraIDPlatformNotRegisteredError(MudraIDError):
    """The URL host does not map to any platform this agent is registered with.

    Raised by the agent SDK when the developer calls
    ``agent.get("https://example.com/...")`` but ``example.com`` is
    not in the agent's bootstrap response — either because the agent
    has not been granted access to that platform, the platform's
    verification has lapsed, or platform-integration-service was
    unavailable when the bootstrap built its host→platform_id map
    and the hostname enrichment came back ``null``.

    Recovery: grant the platform in the MudraID portal, then call
    :py:meth:`mudraid.Agent.refresh_platforms` (or recreate the
    Agent) to re-fetch the map.
    """


class MudraIDRateLimitedError(MudraIDNetworkError):
    """MudraID refused the call because it arrived too fast.

    Not a defect and not a credential problem — the credentials were never
    examined. Something upstream declined to do the work yet.

    WHICH LIMIT WAS HIT IS NOT ALWAYS KNOWABLE FROM THE RESPONSE, and this
    class does not pretend otherwise. Control-plane calls pass through layered
    limiting:

    * identity-service meters the credential-accepting endpoints per
      ``api_key_id`` — ``/auth/token``, ``/auth/verify`` and the bootstrap read
      ``/auth/agents/me/platforms`` share ONE counter, so spending it on any of
      them spends it for all three;
    * identity-service separately enforces the ACCOUNT's fair-use ceiling,
      which belongs to the plan rather than the key and may not clear by
      waiting;
    * the gateway limits the whole identity-service surface, keyed by caller
      source rather than by key — so a busy neighbour behind the same egress
      address can spend it.

    The message names a specific limiter only when the response body identifies
    one; otherwise it says the layer is unknown. A confident wrong attribution
    would send someone to throttle one agent over a limit that was never
    theirs.

    SUBCLASSES :class:`MudraIDNetworkError` DELIBERATELY, for callers who
    already have handling. Before this class existed a 429 fell through to the
    generic non-2xx branch and raised ``MudraIDNetworkError`` — so any code
    catching that today keeps catching this, and only code that WANTS the
    distinction has to change.

    THE SDK DOES NOT SLEEP AND RETRY ON YOUR BEHALF. A bounded wait of up to a
    minute inside a library call is indistinguishable from a hang, and the
    bootstrap this most often guards runs once at start-up where a silent
    stall is worst. The delay the server asked for is handed back instead, so
    the caller decides:

        try:
            agent.get(url)
        except MudraIDRateLimitedError as exc:
            time.sleep(exc.retry_after_seconds or 60)

    ``retry_after_seconds`` is ``None`` when the server sent no ``Retry-After``
    header or sent one that could not be parsed — an absence, never a guessed
    number, so a caller can tell "wait this long" from "wait, length unknown".
    """

    def __init__(self, message: str, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class MudraIDBillingFrozenError(MudraIDNetworkError):
    """MudraID refused because of the ACCOUNT'S PLAN, not the call.

    Raised on HTTP 402 from the control plane. Identity-service answers 402 when
    the agent's ``billing_state`` is ``frozen`` — a state metering writes when a
    trial expires or a subscription is downgraded and the account's agents no
    longer fit under the plan's ceiling. The credentials were verified before
    this refusal, so this is emphatically NOT an authentication failure, and
    nothing about the request was wrong.

    THE DISTINCTION THAT MATTERS IS FROM ``MudraIDRateLimitedError``. Both are
    refusals a plan can cause, and they have opposite remedies. A rate limit
    clears by waiting — the server usually says how long. A freeze does not
    clear by waiting at all: the plan has to change, or the freeze has to be
    lifted, before any retry can succeed. A caller that treats this as transient
    will back off for ever against a state that is not moving.

    SUBCLASSES :class:`MudraIDNetworkError` DELIBERATELY, for the same reason
    :class:`MudraIDRateLimitedError` does. Before this class existed a 402 fell
    through to the generic non-2xx branch and raised ``MudraIDNetworkError``, so
    any code catching that today keeps catching this, and only code that WANTS
    the distinction has to change. The inheritance is a compatibility promise,
    not a claim that this is a network problem.

    The message carries the server's own sentence when it sent one — that
    sentence names the remedy and the screen it lives on, and the SDK is the
    only channel the integrator has. When the server sent nothing usable, the
    message says what the status means and where to look, and does **not**
    invent the specific state that produced it.
    """
