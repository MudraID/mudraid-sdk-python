"""Explicit V2 configuration. Never discover files or fall back to another identity."""

from __future__ import annotations

import os
import re
from pathlib import Path

from mudraid._machine_auth import (
    AssertionSigner,
    ClientSecretIdentity,
    MachineIdentity,
    PyJWTSigner,
)
from mudraid._scopes import RequestedScopes
from mudraid.exceptions import MudraIDConfigError


def load_machine_identity(
    prefix: str, *, signer: AssertionSigner | None = None
) -> MachineIdentity | ClientSecretIdentity:
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prefix):
        raise MudraIDConfigError("prefix must be a non-empty environment-variable name fragment")

    def required(name: str) -> str:
        variable = f"{prefix}_{name}"
        value = os.environ.get(variable, "").strip()
        if not value:
            raise MudraIDConfigError(f"Set {variable} for the machine client")
        return value

    # Read the complete identity before opening a key file. Failure remains
    # local; an unprefixed or legacy credential never repairs missing input.
    client_id = required("CLIENT_ID")
    token_endpoint = required("TOKEN_ENDPOINT")
    resource = required("RESOURCE")
    scopes = RequestedScopes.of(os.environ.get(f"{prefix}_SCOPES", "").split())

    method = os.environ.get(f"{prefix}_AUTH_METHOD", "private_key_jwt").strip()
    if method == "client_secret_basic":
        if signer is not None:
            raise MudraIDConfigError("Choose client secret or signing key, not both")
        return ClientSecretIdentity(
            client_id=client_id,
            token_endpoint=token_endpoint,
            resource=resource,
            scopes=scopes,
            client_secret=required("CLIENT_SECRET"),
        )
    if method != "private_key_jwt":
        raise MudraIDConfigError("AUTH_METHOD must be private_key_jwt or client_secret_basic")
    audience = required("ASSERTION_AUDIENCE")

    if signer is None:
        key_path = required("PRIVATE_KEY_PATH")
        kid = required("KEY_ID")
        try:
            private_key = Path(key_path).read_bytes()
        except (OSError, ValueError):
            # Do not include the configured path or chained OS exception: a
            # mistaken configuration may itself contain credential material.
            raise MudraIDConfigError(
                f"Cannot read the key file named by {prefix}_PRIVATE_KEY_PATH"
            ) from None
        if not private_key.strip():
            raise MudraIDConfigError(f"The key file named by {prefix}_PRIVATE_KEY_PATH is empty")
        signer = PyJWTSigner(private_key, kid=kid)

    return MachineIdentity(
        client_id=client_id,
        token_endpoint=token_endpoint,
        audience=audience,
        resource=resource,
        scopes=scopes,
        signer=signer,
    )
