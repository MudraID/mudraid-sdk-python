"""mudraid — Python SDK for MudraID.

Two auth profiles are exposed:

  * :class:`Agent` — the *legacy* profile: a drop-in replacement for ``requests``
    that authenticates with an api_key_id/secret pair and routes per registered
    platform. Retained additively; see :meth:`Agent.legacy` and the class
    docstring's retirement policy.
  * :class:`MachineAgent` — the *V2 machine-authority* profile:
    ``private_key_jwt`` client-assertion auth with explicit audience + scopes,
    resource/scope-bound access tokens, and consequence-safe retry. An omitted
    scope set is the empty (minimal) set — never a wildcard — and a consequential
    call whose outcome is unknown is never blindly replayed.
"""

from mudraid._agent import Agent
from mudraid._consequence import IDEMPOTENCY_KEY_HEADER, is_idempotent
from mudraid._machine_agent import MachineAgent
from mudraid._machine_auth import (
    AssertionSigner,
    MachineIdentity,
    MachineTokenManager,
    PyJWTSigner,
    build_client_assertion_claims,
)
from mudraid._scopes import RequestedScopes
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDBillingFrozenError,
    MudraIDConfigError,
    MudraIDError,
    MudraIDExecutionUnknownError,
    MudraIDNetworkError,
    MudraIDPlatformNotRegisteredError,
    MudraIDRateLimitedError,
    MudraIDRevokedError,
    MudraIDScopeError,
)

__all__ = [
    # Legacy profile
    "Agent",
    # V2 machine-authority profile
    "MachineAgent",
    "MachineIdentity",
    "MachineTokenManager",
    "AssertionSigner",
    "PyJWTSigner",
    "RequestedScopes",
    "build_client_assertion_claims",
    "IDEMPOTENCY_KEY_HEADER",
    "is_idempotent",
    # Errors
    "MudraIDError",
    "MudraIDConfigError",
    "MudraIDAuthError",
    "MudraIDRevokedError",
    "MudraIDNetworkError",
    "MudraIDPlatformNotRegisteredError",
    "MudraIDRateLimitedError",
    "MudraIDScopeError",
    "MudraIDBillingFrozenError",
    "MudraIDExecutionUnknownError",
]

__version__ = "1.2.0"
