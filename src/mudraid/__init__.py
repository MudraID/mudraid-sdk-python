"""MudraID SDK: linked OAuth authority for outbound agent requests.

Agent and MachineAgent use the same implementation and explicit grants.
"""

from mudraid._consequence import IDEMPOTENCY_KEY_HEADER, is_idempotent
from mudraid._machine_agent import MachineAgent
from mudraid._machine_auth import (
    AssertionSigner,
    ClientSecretIdentity,
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
    MudraIDRateLimitedError,
    MudraIDRevokedError,
    MudraIDScopeError,
)

Agent = MachineAgent

__all__ = [
    "Agent",
    "MachineAgent",
    "MachineIdentity",
    "ClientSecretIdentity",
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
    "MudraIDRateLimitedError",
    "MudraIDScopeError",
    "MudraIDBillingFrozenError",
    "MudraIDExecutionUnknownError",
]

__version__ = "2.0.0"
