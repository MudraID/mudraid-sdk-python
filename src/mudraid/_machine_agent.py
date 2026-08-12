"""MachineAgent — the V2 machine-authority HTTP client.

The V2 counterpart to :class:`mudraid.Agent`. Where the legacy ``Agent``
authenticates with an api_key_id/secret pair and routes per registered platform,
``MachineAgent`` authenticates with a ``private_key_jwt`` client assertion
(:class:`mudraid.MachineIdentity`), carries a resource/scope-bound V2 access
token, and applies consequence-safe retry semantics to every call.

Two safety invariants are enforced here end to end:

  1. **Empty scope never means all.** Authority comes from the identity's
     :class:`RequestedScopes`, which cannot express a wildcard; an omitted scope
     set travels as no ``scope`` field and is read by the server as least
     privilege (see :mod:`mudraid._machine_auth` / :mod:`mudraid._scopes`).
  2. **No blind replay of an ambiguous consequential call.** Every request runs
     through :func:`mudraid._consequence.execute`: an idempotent method or a
     pre-response failure may be retried, but a consequential method
     (``POST``/``PATCH``) that was sent without a response and without an
     idempotency key is never replayed — it raises
     :class:`mudraid.MudraIDExecutionUnknownError` instead.

On a resource-server ``401`` the token is refreshed once and the request is
replayed — but only when replaying is itself consequence-safe (idempotent method
or an idempotency key), so 401 recovery never becomes a backdoor that duplicates
a consequential action.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from mudraid._consequence import IDEMPOTENCY_KEY_HEADER, execute, is_idempotent
from mudraid._machine_auth import MachineIdentity, MachineTokenManager

_logger = logging.getLogger("mudraid.machine_agent")


class MachineAgent:
    """Authenticated, consequence-safe HTTP client for one machine identity."""

    def __init__(
        self,
        identity: MachineIdentity,
        *,
        token_manager: MachineTokenManager | None = None,
    ) -> None:
        self._identity = identity
        # The token manager owns its own session to the token endpoint; a
        # separate session carries the issued bearer to resource servers so the
        # assertion and the access token never share a connection or headers.
        self._tokens = token_manager or MachineTokenManager(identity)
        self._session = requests.Session()
        _logger.info(
            "MachineAgent created: client_id=%s resource=%s",
            identity.client_id,
            identity.resource,
        )

    # ---- safe-to-read accessors ----------------------------------------

    @property
    def client_id(self) -> str:
        """The public machine-client identifier. Safe to log/display."""
        return self._identity.client_id

    @property
    def resource(self) -> str:
        """The resource indicator issued tokens are bound to."""
        return self._identity.resource

    # ---- HTTP surface ---------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("OPTIONS", url, **kwargs)

    def post(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("POST", url, idempotency_key=idempotency_key, **kwargs)

    def put(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("PUT", url, idempotency_key=idempotency_key, **kwargs)

    def patch(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("PATCH", url, idempotency_key=idempotency_key, **kwargs)

    def delete(
        self, url: str, *, idempotency_key: str | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("DELETE", url, idempotency_key=idempotency_key, **kwargs)

    def close(self) -> None:
        """Release the underlying connection pools. Optional."""
        self._session.close()

    # ---- internals ------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Attach a current V2 token and dispatch with consequence-safe retry.

        A resource-server ``401`` triggers exactly one token refresh + replay —
        but only when replaying is consequence-safe. For a consequential method
        with no idempotency key we do NOT replay a 401 either: a 401 *after* the
        server mutated state would otherwise be duplicated. In that case the
        original 401 response is returned for the caller to handle.
        """
        caller_headers = dict(kwargs.pop("headers", None) or {})

        def send(extra_headers: dict[str, str]) -> requests.Response:
            token = self._tokens.get_token()
            headers = {
                **caller_headers,
                **extra_headers,
                "Authorization": f"Bearer {token}",
            }
            return self._session.request(method=method, url=url, headers=headers, **kwargs)

        response = execute(send, method=method, idempotency_key=idempotency_key)
        if response.status_code != 401:
            return response

        # Token rejected. Refresh once and replay — but only if replaying is
        # consequence-safe, so 401 recovery cannot duplicate a consequential
        # action whose first attempt may already have taken effect.
        if not (is_idempotent(method) or idempotency_key):
            _logger.warning(
                "401 on consequential %s with no idempotency key; not replaying "
                "(a post-mutation 401 must not be duplicated) — returning the 401",
                method,
            )
            return response

        _logger.warning(
            "resource server returned 401 for %s %s; refreshing token and retrying once",
            method,
            url,
        )
        self._tokens.refresh()
        return execute(send, method=method, idempotency_key=idempotency_key)


__all__ = ["MachineAgent", "IDEMPOTENCY_KEY_HEADER"]
