"""The ``[v2]`` extra, exercised rather than merely installed.

WHY THIS FILE EXISTS
====================

``PyJWTSigner`` is the only thing in this SDK that needs the ``[v2]`` extra,
and its one method that touches PyJWT — :meth:`PyJWTSigner.sign` — was never
called by any test. The suite covered the constructor thoroughly: which
algorithms it refuses, which it accepts, what it stores. Every one of those
assertions passes with PyJWT absent, because the import is lazy and the
constructor never reaches it.

So the release pipeline could install ``[v2]``, resolve its dependency floors,
report a full green, and still have produced no evidence that a customer who
runs ``pip install mudraid-sdk[v2]`` can sign anything. Installing an extra is
not the same fact as exercising it, and only one of them is worth a passing
test count.

These tests sign for real and verify the result with the public half of the
key, which is the only assertion that can distinguish "PyJWT is importable"
from "the assertion we hand the authorization server is a valid one".

WHY IT SKIPS RATHER THAN FAILS WITHOUT THE EXTRA
------------------------------------------------

The extra is optional by design — the SDK core carries no crypto dependency —
so a contributor running ``pip install -e .[dev]`` legitimately has no PyJWT,
and failing there would punish the supported development shape.

A skip is only safe because the RELEASE pipeline does not rely on it: publish.yml
installs ``[v2,dev]`` and then asserts, in its own step, that ``jwt`` and
``cryptography`` import. If the extra is ever dropped or fails to resolve, that
step fails the job — so these tests can never be silently skipped in the run
that matters, which is the difference between a skip and a hole.
"""

from __future__ import annotations

import pytest

jwt = pytest.importorskip("jwt", reason="the [v2] extra is not installed")
pytest.importorskip("cryptography", reason="the [v2] extra is not installed")

from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from mudraid import PyJWTSigner  # noqa: E402

CLAIMS = {
    "iss": "client-abc",
    "sub": "client-abc",
    "aud": "https://api.mudraid.ai/oauth2/token",
    "jti": "b6d8f2c0-0f1a-4f5e-9d3a-2c7e5a1b4d90",
    "exp": 4102444800,  # 2100-01-01, so this never expires under test
}


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_a_signed_assertion_verifies_against_the_public_key(rsa_key) -> None:
    """The whole point of the extra: an assertion the server can actually check.

    Verification is done with the PUBLIC key, which is what the authorization
    server holds. Decoding with the private key would prove only that PyJWT is
    self-consistent and would pass just as well for a symmetric algorithm —
    the exact thing this signer refuses.
    """
    signer = PyJWTSigner(rsa_key, kid="key-1")

    token = signer.sign(CLAIMS)

    decoded = jwt.decode(
        token,
        rsa_key.public_key(),
        algorithms=["RS256"],
        audience=CLAIMS["aud"],
    )
    assert decoded == CLAIMS


def test_the_kid_reaches_the_header_so_the_server_can_select_a_key(rsa_key) -> None:
    """A server with several registered keys picks by ``kid``. Without it in the
    HEADER — not the payload — it has to guess, and a correct signature under a
    key it cannot find reads to it as an invalid one."""
    token = PyJWTSigner(rsa_key, kid="key-42").sign(CLAIMS)

    header = jwt.get_unverified_header(token)
    assert header["kid"] == "key-42"
    assert header["alg"] == "RS256"


def test_a_non_default_asymmetric_algorithm_signs_and_verifies() -> None:
    """The constructor accepts the whole asymmetric set; this proves one of the
    non-default members survives the round trip rather than merely being stored.
    ES256 needs a matching curve, so this is also the test that would catch the
    signer passing a key type PyJWT rejects for the chosen algorithm."""
    key = ec.generate_private_key(ec.SECP256R1())
    signer = PyJWTSigner(key, kid="ec-1", algorithm="ES256")

    token = signer.sign(CLAIMS)

    assert jwt.get_unverified_header(token)["alg"] == "ES256"
    assert jwt.decode(
        token, key.public_key(), algorithms=["ES256"], audience=CLAIMS["aud"]
    ) == CLAIMS


def test_the_signature_is_over_the_claims_we_passed(rsa_key) -> None:
    """A tampered payload must not verify. Asserted because 'it decodes' and
    'it is protected' are different properties, and the first is what a test
    that only calls decode() on an untouched token measures."""
    token = PyJWTSigner(rsa_key, kid="key-1").sign(CLAIMS)
    head, payload, signature = token.split(".")
    other = PyJWTSigner(rsa_key, kid="key-1").sign({**CLAIMS, "sub": "someone-else"})
    swapped = f"{head}.{other.split('.')[1]}.{signature}"

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            swapped, rsa_key.public_key(), algorithms=["RS256"], audience=CLAIMS["aud"]
        )


def test_the_private_key_is_not_in_the_token(rsa_key) -> None:
    """The signer holds key material. Nothing derived from it may travel in the
    assertion beyond the signature itself — a key accidentally placed in a
    header or claim would be published to every server the client talks to."""
    token = PyJWTSigner(rsa_key, kid="key-1").sign(CLAIMS)

    header = jwt.get_unverified_header(token)
    assert "jwk" not in header, "the private key's JWK must never be embedded"
    assert "x5c" not in header
    assert set(header) == {"alg", "typ", "kid"}
