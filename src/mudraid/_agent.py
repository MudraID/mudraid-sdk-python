"""Agent — public entry point of the MudraID SDK.

Each call:

  1. Resolves the URL's host to a ``platform_id`` via
     :class:`mudraid._platform_resolver.PlatformResolver`.
  2. Asks :class:`mudraid._token_manager.TokenManager` for a current
     JWT for that platform (cache hit, or mint on miss).
  3. Injects ``Authorization: Bearer <jwt>`` into the outgoing
     ``requests`` call, preserving every other ``requests`` kwarg.
  4. Runs the request under consequence-safe retry semantics
     (:mod:`mudraid._consequence`) and returns the
     :class:`requests.Response`.

The class mirrors :class:`requests.Session` so an integrator's diff
is "``import requests``" → "``from mudraid import Agent``".

Consequence safety
------------------

This client will not replay a request whose replay could duplicate a
side effect. That applies to both ways a replay can arise:

  * a **transport failure** where the request was sent and no response
    was read, and
  * a resource-server **401**, where the token is refreshed and the
    call retried.

For ``GET``/``HEAD``/``OPTIONS``/``PUT``/``DELETE`` a replay cannot
duplicate an effect, so it happens as before. For ``POST``/``PATCH``
it happens only when the caller supplies an ``idempotency_key`` the
server deduplicates on. Without one, the 401 is returned to the caller
unreplayed and an ambiguous transport failure raises
:class:`mudraid.MudraIDExecutionUnknownError`.

This is the same rule :class:`mudraid.MachineAgent` applies. It used to
differ here, and the difference mattered: a platform that mutated state
and *then* answered 401 had the mutation performed twice, and the caller
saw a clean success from the second attempt with nothing to indicate the
first had landed.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from mudraid._consequence import execute, is_idempotent
from mudraid._env import SdkConfig, load_config
from mudraid._http import MudraIDHttpClient
from mudraid._platform_resolver import PlatformResolver
from mudraid._token_manager import TokenManager

_logger = logging.getLogger("mudraid.agent")


class Agent:
    """Authenticated HTTP client that speaks for one MudraID agent.

    .. note:: **Legacy machine-authority profile.**

        This class is the *legacy* auth profile: it authenticates with an
        api_key_id/secret pair against ``POST /api/v1/auth/token`` and — by
        design — lets an empty ``scopes`` request expand to the agent's *full*
        permitted set on the platform. The V2 machine-authority profile
        (:class:`mudraid.MachineAgent` /
        :class:`mudraid.MachineIdentity`), where a ``private_key_jwt`` assertion
        carries explicit audience + scopes and an omitted scope set means the
        *empty* (minimal) set, never "everything."

        The legacy profile stays fully supported and reachable — additively, so
        existing integrations do not break — and can be selected explicitly via
        :meth:`Agent.legacy` to make the choice visible at call sites.

        **Retirement policy:** the legacy profile is retained through the V2
        transition and is scheduled for removal in a future major SDK release
        once V2 machine authority is generally available; it will be deprecated
        (with a runtime warning and a migration window) before any removal. New
        integrations should adopt :class:`mudraid.MachineAgent`.

    Construction resolves credentials with the following precedence:

      1. Explicit keyword arguments (``api_key_id=``, ``secret=``,
         ``base_url=``)
      2. The OS environment (``MUDRAID_API_KEY_ID``, ``MUDRAID_SECRET``,
         ``MUDRAID_BASE_URL``)
      3. A ``.env`` file in the project tree (auto-discovered)

    Multi-agent applications can give each agent its own variables with
    ``prefix``: the prefix replaces the ``MUDRAID`` segment of the names, so
    ``Agent(prefix="SUPERVISOR")`` reads ``SUPERVISOR_API_KEY_ID`` and
    ``SUPERVISOR_SECRET`` (and ``SUPERVISOR_BASE_URL`` if set, falling back
    to the shared ``MUDRAID_BASE_URL``). Prefixed credentials never fall
    back to the unprefixed pair — a missing prefixed variable is an error
    naming exactly the variables that were consulted.

    Raises:
        MudraIDConfigError: when ``api_key_id`` or ``secret`` cannot
            be resolved from any of the above, or when ``prefix`` is not a
            usable env-var name fragment. ``base_url`` always has a
            sensible production default and never raises on its own.

    The first outgoing request triggers a one-time bootstrap call to
    MudraID to learn which platforms this agent is registered with.
    Subsequent calls are cache-warm.
    """

    def __init__(
        self,
        api_key_id: str | None = None,
        secret: str | None = None,
        base_url: str | None = None,
        prefix: str | None = None,
    ) -> None:
        self._config: SdkConfig = load_config(
            api_key_id=api_key_id,
            secret=secret,
            base_url=base_url,
            prefix=prefix,
        )
        # api_key_id is public; base_url is public. Logging both is
        # safe and useful for "which agent did this?" debugging.
        _logger.info(
            "Agent created: api_key_id=%s base_url=%s",
            self._config.api_key_id,
            self._config.base_url,
        )
        self._mudraid_http = MudraIDHttpClient(self._config)
        self._tokens = TokenManager(self._mudraid_http)
        self._platforms = PlatformResolver(self._mudraid_http)
        # A separate Session for outgoing platform calls. We do NOT
        # share the MudraID session because the two have different
        # security properties: MudraID requests carry the agent's
        # plaintext secret in the body; platform requests carry the
        # short-lived JWT in a header. Keeping the sessions distinct
        # makes it impossible to accidentally send one's headers on
        # the other's connection.
        self._platform_session = requests.Session()

    @classmethod
    def legacy(
        cls,
        api_key_id: str | None = None,
        secret: str | None = None,
        base_url: str | None = None,
        prefix: str | None = None,
    ) -> "Agent":
        """Explicitly construct the legacy api_key_id/secret auth profile.

        Behaviourally identical to calling ``Agent(...)`` directly — the default
        constructor *is* the legacy profile — but naming it at the call site
        documents the choice now that the V2 profile
        (:class:`mudraid.MachineAgent`) exists. Provided so integrations can pin
        themselves to the legacy behaviour intentionally rather than by default,
        and so a future deprecation can target this explicit entry point. See the
        class docstring for the retirement policy.
        """
        _logger.info("Agent.legacy() — constructing the legacy auth profile explicitly")
        return cls(api_key_id=api_key_id, secret=secret, base_url=base_url, prefix=prefix)

    # ---- public, safe-to-read accessors ---------------------------------

    @property
    def api_key_id(self) -> str:
        """The public agent identifier (``muid_kid_...``).

        Safe to log and display — this is the public half of the
        credential pair. The secret is intentionally not exposed via
        any property.
        """
        return self._config.api_key_id

    @property
    def base_url(self) -> str:
        """Resolved MudraID API base URL.

        Useful for diagnostics and dev tooling that need to confirm
        the SDK is pointed at the right backend.
        """
        return self._config.base_url

    # ---- maintenance ----------------------------------------------------

    def refresh_platforms(self) -> None:
        """Force a fresh bootstrap of the platform map.

        Call this after granting a new platform to the agent in the
        portal, or after removing one. The next outgoing request
        triggers a re-fetch of ``/auth/agents/me/platforms`` and
        rebuilds the host→platform_id map. Cached JWTs are also
        dropped so a now-revoked platform cannot serve a stale token.
        """
        _logger.info("Agent.refresh_platforms() — clearing resolver + token caches")
        self._platforms.refresh()
        self._tokens.clear()

    def close(self) -> None:
        """Release the underlying HTTP connection pools.

        Optional — both sessions garbage-collect cleanly. Provided for
        scripts that want deterministic shutdown.
        """
        self._platform_session.close()
        self._mudraid_http.close()

    # ---- HTTP surface ---------------------------------------------------

    # The idempotent verbs take no ``idempotency_key``: replaying them cannot
    # duplicate an effect, so nothing about their retry behaviour depends on one.
    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("OPTIONS", url, **kwargs)

    # ``idempotency_key`` is what makes a replay of a consequential call safe:
    # the server collapses the duplicate. The signature mirrors
    # :class:`mudraid.MachineAgent` exactly, so moving between the two profiles
    # is not also a change of retry semantics.
    def post(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("POST", url, idempotency_key=idempotency_key, **kwargs)

    def patch(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("PATCH", url, idempotency_key=idempotency_key, **kwargs)

    # PUT and DELETE are idempotent, so a key is not needed for SDK-side safety.
    # It is accepted anyway — a server may still want to deduplicate, and
    # refusing the argument here would make the two clients disagree.
    def put(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("PUT", url, idempotency_key=idempotency_key, **kwargs)

    def delete(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("DELETE", url, idempotency_key=idempotency_key, **kwargs)

    # ---- internals ------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """The single point through which every HTTP method flows.

        Behaviour:

          - Resolves the URL host → platform_id. Failure here raises
            ``MudraIDPlatformNotRegisteredError`` BEFORE any outbound
            HTTP call.
          - Asks TokenManager for a JWT for the platform. Failure
            here raises ``MudraIDAuthError`` / ``MudraIDRevokedError``
            / ``MudraIDNetworkError`` BEFORE the platform is contacted.
          - Sends the request with ``Authorization: Bearer <jwt>``,
            under :func:`mudraid._consequence.execute` so an ambiguous
            transport failure is never blindly replayed.
          - On a platform ``401``, refreshes the JWT and replays the
            request EXACTLY ONCE — **when replaying is consequence-safe**.
            A second 401 is surfaced to the caller; we never loop. Any
            other status (200, 4xx, 5xx) is returned unmodified.

        WHY THE 401 REPLAY IS CONDITIONAL. It used to be unconditional,
        defended by the argument that a 401 proves the platform rejected
        the request *before* processing it, so the replay is the first
        time the call is really seen. That argument is about a platform
        the SDK does not control and cannot inspect. A server that writes
        and then fails to renew its own auth check, a proxy that turns an
        expired session into a 401 after forwarding, a gateway that
        answers 401 on the response path — each produces a 401 that
        arrives *after* the effect. The SDK cannot distinguish those from
        the benign case, and the cost of being wrong is a duplicated
        payment, message or deletion, reported to the caller as a clean
        success from the second attempt.

        So the rule is the one :class:`mudraid.MachineAgent` already
        applies: replay when replaying provably cannot duplicate an
        effect — an idempotent method, or a caller-supplied
        ``idempotency_key`` the server deduplicates on. Otherwise return
        the 401 and let the caller decide, which is the only party that
        knows whether the action is safe to repeat.
        """
        platform_id = self._platforms.resolve(url)

        # Pop the caller's headers exactly once so each attempt sees a clean
        # copy. Without this, a ``kwargs.pop`` inside the retry would silently
        # drop the caller's headers on the second attempt.
        caller_headers = dict(kwargs.pop("headers", None) or {})

        def send(extra_headers: dict[str, str]) -> requests.Response:
            """Attach a current JWT and dispatch one HTTP request.

            Header merge policy: caller-supplied entries first, then the
            consequence layer's ``Idempotency-Key``, then the SDK's
            ``Authorization`` last so it always wins. A developer passing their
            own ``Authorization`` is almost certainly using a different auth
            mechanism; overriding is correct because attaching the MudraID
            bearer token is what this client is for.

            The token is fetched per attempt rather than captured once, so a
            replay after ``TokenManager.refresh`` carries the fresh one.
            """
            token = self._tokens.get_token(platform_id)
            headers = {
                **caller_headers,
                **extra_headers,
                "Authorization": f"Bearer {token}",
            }
            return self._platform_session.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs,
            )

        response = execute(send, method=method, idempotency_key=idempotency_key)
        if response.status_code != 401:
            return response

        if not (is_idempotent(method) or idempotency_key):
            # Consequential, unkeyed, and the outcome of the first attempt is
            # not knowable from here. Returning the 401 is the honest answer:
            # the caller learns authentication failed and decides whether the
            # action is safe to repeat. Replaying would decide that for them.
            _logger.warning(
                "platform returned 401 for %s %s; NOT replaying a consequential "
                "call with no idempotency key (a post-mutation 401 would be "
                "duplicated) — returning the 401. Pass idempotency_key= to make "
                "the replay safe.",
                method,
                url,
            )
            return response

        _logger.warning(
            "platform returned 401 for %s %s; refreshing token and retrying once",
            method,
            url,
        )
        self._tokens.refresh(platform_id)
        return execute(send, method=method, idempotency_key=idempotency_key)
