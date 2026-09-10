"""V2 redirect refusal, asymmetric signing algorithms and token-type checks."""

from __future__ import annotations

import pytest
import responses

from mudraid import MudraIDNetworkError
from mudraid._machine_auth import (
    MachineIdentity,
    MachineTokenManager,
    PyJWTSigner,
)

V2_TOKEN_ENDPOINT = "https://identity.mudraid.test/oauth2/token"


class _RecordingSigner:
    """A fake :class:`AssertionSigner` — no crypto, records what it was asked."""

    def __init__(self, assertion: str = "signed.client.assertion") -> None:
        self._assertion = assertion
        self.claims: list[dict] = []

    def sign(self, claims: dict) -> str:
        self.claims.append(dict(claims))
        return self._assertion


def _identity(**overrides) -> MachineIdentity:
    kwargs = {
        "client_id": "mc_test",
        "token_endpoint": V2_TOKEN_ENDPOINT,
        "audience": V2_TOKEN_ENDPOINT,
        "resource": "https://api.example.test/mcp",
        "signer": _RecordingSigner(),
    }
    kwargs.update(overrides)
    return MachineIdentity(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. Control-plane POSTs do not follow redirects
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 2. MUDRAID_BASE_URL transport
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 3. The V2 token endpoint holds the same line
# ---------------------------------------------------------------------------


def test_token_endpoint_redirect_is_refused_not_followed() -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            V2_TOKEN_ENDPOINT,
            status=307,
            headers={"Location": "https://collector.attacker.test/harvest"},
        )
        manager = MachineTokenManager(_identity())
        with pytest.raises(MudraIDNetworkError, match="redirect"):
            manager.get_token()

        assert len(rsps.calls) == 1


# ---------------------------------------------------------------------------
# 4. private_key_jwt signs asymmetrically or not at all
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("algorithm", "why"),
    [
        ("none", "an unsigned assertion is not a proof of anything"),
        ("HS256", "symmetric: the 'private' key becomes a secret the server holds too"),
        ("HS512", "same, wider"),
        ("", "empty is not an algorithm"),
        ("rs256", "case matters — PyJWT's registry is exact"),
    ],
)
def test_a_non_asymmetric_assertion_algorithm_is_refused(algorithm: str, why: str) -> None:
    with pytest.raises(ValueError, match="not a permitted client-assertion algorithm"):
        PyJWTSigner("key-material", kid="k1", algorithm=algorithm)


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_the_two_server_verified_algorithms_are_accepted(algorithm: str) -> None:
    signer = PyJWTSigner("key-material", kid="k1", algorithm=algorithm)
    assert signer._algorithm == algorithm  # noqa: SLF001 - asserting the stored choice


@pytest.mark.parametrize(
    "algorithm",
    ["RS384", "RS512", "PS256", "PS384", "PS512", "ES384", "ES512", "ES256K", "EdDSA"],
)
def test_an_asymmetric_algorithm_the_server_does_not_verify_is_refused_early(
    algorithm: str,
) -> None:
    """KAN-171. These are asymmetric and PyJWT encodes them, and the SDK used
    to accept all nine. The server verifies exactly RS256 and ES256, so a
    client configured with any of these signed a well-formed assertion and
    was refused with a uniform invalid_client that -- by design -- does not
    say why. The SDK is the one component that can refuse early and explain,
    and the sentence must be the ASYMMETRIC one: sending someone who chose
    ES384 to read about 'none' and 'HS256' is the wrong help."""
    with pytest.raises(ValueError) as caught:
        PyJWTSigner("key-material", kid="k1", algorithm=algorithm)
    message = str(caught.value)
    assert "not a permitted client-assertion algorithm" in message
    assert "exactly RS256 and ES256" in message
    assert "unsigned" not in message


def test_the_advertised_set_is_exactly_what_the_server_verifies() -> None:
    """The constant IS the contract with the server. If the server ever widens
    its verifier this assertion is the reminder that the client follows the
    server, never the other way round."""
    from mudraid._machine_auth import _PERMITTED_ASSERTION_ALGORITHMS  # noqa: PLC0415

    assert _PERMITTED_ASSERTION_ALGORITHMS == frozenset({"RS256", "ES256"})


#: The two real-key factories below need the optional ``[v2]`` extra (PyJWT +
#: cryptography). The SDK core carries no crypto dependency by design, and the
#: Agent SDK CI job installs ``[dev]`` alone, so without the extra these SKIP —
#: the same posture as ``test_machine_auth_v2_extra.py`` and safe for the same
#: reason: the release pipeline installs ``[v2,dev]`` and asserts the imports.
_V2_EXTRA_REASON = "the [v2] extra is not installed"


def _rsa_2048_key():
    rsa = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.rsa", reason=_V2_EXTRA_REASON
    )
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _p256_key():
    ec = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ec", reason=_V2_EXTRA_REASON
    )
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize(
    ("algorithm", "make_key"),
    [("RS256", _rsa_2048_key), ("ES256", _p256_key)],
)
def test_both_supported_algorithms_produce_an_assertion_that_verifies(
    algorithm: str, make_key
) -> None:
    """Not a mock: a real key of the right type, a real signature, verified
    under the server's own rules -- the algorithm pinned to the one the header
    claims, the ``kid`` present, the audience checked. This is the half of the
    algorithm contract a refusal test cannot prove: that the two the SDK keeps
    actually work."""
    jwt = pytest.importorskip("jwt", reason=_V2_EXTRA_REASON)

    private_key = make_key()
    signer = PyJWTSigner(private_key, kid="k-2026", algorithm=algorithm)
    assertion = signer.sign(
        {
            "iss": "muid_mc_x",
            "sub": "muid_mc_x",
            "aud": "https://id.example/oauth2/token",
            "jti": "j1",
            "iat": 1_787_000_000,
            "exp": 1_787_000_180,
        }
    )
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == algorithm
    assert header["kid"] == "k-2026"
    claims = jwt.decode(
        assertion,
        private_key.public_key(),
        algorithms=[algorithm],  # pinned, exactly as the verifier pins it
        audience="https://id.example/oauth2/token",
        options={"verify_exp": False},
    )
    assert claims["sub"] == "muid_mc_x"


def test_the_default_algorithm_is_still_rs256() -> None:
    assert PyJWTSigner("key-material", kid="k1")._algorithm == "RS256"  # noqa: SLF001


# ---------------------------------------------------------------------------
# 5. A non-bearer token is not presented as a bearer token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token_type", ["mac", "DPoP", "N_A"])
def test_a_non_bearer_token_type_is_refused(token_type: str) -> None:
    """These types are protected by a binding this SDK does not implement.
    Sending one as ``Authorization: Bearer`` uses the credential outside the
    thing that makes it safe."""
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            V2_TOKEN_ENDPOINT,
            json={"access_token": "tok", "token_type": token_type, "expires_in": 300},
            status=200,
        )
        with pytest.raises(MudraIDNetworkError, match="will not present another type"):
            MachineTokenManager(_identity()).get_token()


@pytest.mark.parametrize("token_type", ["Bearer", "bearer", "BEARER", None])
def test_bearer_and_an_omitted_type_are_both_accepted(token_type: str | None) -> None:
    """``token_type`` is RFC-required and widely omitted; absence must stay
    workable, and the comparison is case-insensitive per RFC 6749 §5.1."""
    body = {"access_token": "tok", "expires_in": 300}
    if token_type is not None:
        body["token_type"] = token_type
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, V2_TOKEN_ENDPOINT, json=body, status=200)
        assert MachineTokenManager(_identity()).get_token() == "tok"
