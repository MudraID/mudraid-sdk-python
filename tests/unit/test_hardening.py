"""Hardening regressions for the SDK's credential handling.

Everything here defends ONE property: the agent's long-lived secret and its
short-lived signed assertion go to the place they were meant for, over a
transport that keeps them, and nowhere else. Each test holds a defect that was
present and is now closed.

  1. **Control-plane POSTs do not follow redirects.** ``POST /api/v1/auth/token``
     and the platform bootstrap both send ``{"api_key_id", "secret"}`` as a JSON
     body. ``requests`` follows redirects by default and REPLAYS the body on
     307/308; ``Session.rebuild_auth`` strips a cross-host Authorization *header*
     and has no equivalent for a body. The secret was therefore one redirect away
     from any host that could answer.
  2. **``MUDRAID_BASE_URL`` must not be cleartext to a remote host.** Same body,
     same secret, read by every hop.
  3. **The token endpoint is held to the same rule**, for the signed assertion.
  4. **``private_key_jwt`` signs asymmetrically or not at all.** PyJWT will
     happily encode ``alg=none`` (unsigned) or ``HS256`` (a shared secret), both
     of which dissolve the profile's whole reason for existing.
  5. **A non-bearer token is not presented as a bearer token.**
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest
import responses

from mudraid import Agent, MudraIDConfigError, MudraIDNetworkError
from mudraid._env import load_config
from mudraid._machine_auth import (
    MachineIdentity,
    MachineTokenManager,
    PyJWTSigner,
)

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"
V2_TOKEN_ENDPOINT = "https://identity.mudraid.test/oauth2/token"


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Same isolation as ``test_env_loader``: no test inherits credentials, and
    ``load_dotenv`` never reaches the repository's real ``.env``."""
    for key in ("MUDRAID_API_KEY_ID", "MUDRAID_SECRET", "MUDRAID_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    import mudraid._env as env_module

    monkeypatch.setattr(env_module, "_dotenv_loaded", False)
    monkeypatch.chdir(tmp_path)
    yield tmp_path


def _agent() -> Agent:
    return Agent(api_key_id="muid_kid_test", secret="muid_sk_test", base_url=MUDRAID_BASE)


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


@pytest.mark.parametrize("redirect_status", [301, 302, 303, 307, 308])
def test_control_plane_redirect_is_refused_not_followed(redirect_status: int) -> None:
    """The secret must not be resent to wherever a Location header points.

    307/308 are the sharp cases — they preserve method AND body, so the
    plaintext secret would arrive at the attacker's host in full. The others are
    refused too: none of them is a legitimate answer from these paths, and a
    rule that holds only for the dangerous status codes is a rule someone has to
    remember.
    """
    evil = "https://collector.attacker.test/harvest"
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            PLATFORMS_URL,
            status=redirect_status,
            headers={"Location": evil},
        )
        agent = _agent()
        with pytest.raises(MudraIDNetworkError, match="redirect"):
            agent.get("https://api.skyscanner.test/flights")

        # Exactly one request, to us. The absence of a second call IS the test:
        # a followed redirect would show up here as a request to `evil`.
        assert len(rsps.calls) == 1
        assert rsps.calls[0].request.url.startswith(MUDRAID_BASE)


def test_the_redirect_refusal_does_not_echo_the_location() -> None:
    """The Location value is attacker-controllable in precisely the scenario the
    refusal exists for. Naming it in an error a developer will paste into a
    ticket just relocates the invitation."""
    evil = "https://collector.attacker.test/harvest"
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, PLATFORMS_URL, status=307, headers={"Location": evil})
        agent = _agent()
        with pytest.raises(MudraIDNetworkError) as caught:
            agent.get("https://api.skyscanner.test/flights")

    message = str(caught.value)
    assert "collector.attacker.test" not in message
    assert "MUDRAID_BASE_URL" in message, "the message should still diagnose the cause"


def test_a_normal_control_plane_call_is_unaffected() -> None:
    """Non-redirect behaviour is untouched — the fix must not cost a working
    integration anything."""
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.POST,
            PLATFORMS_URL,
            json={
                "platforms": [
                    {
                        "platform_id": "plt-1",
                        "hostname": "api.skyscanner.test",
                        "status": "active",
                        "verification_status": "verified",
                    }
                ]
            },
            status=200,
        )
        rsps.add(
            responses.POST,
            TOKEN_URL,
            json={"access_token": "jwt.value.here", "expires_in": 900},
            status=200,
        )
        rsps.add(
            responses.GET, "https://api.skyscanner.test/flights", json={"ok": True}, status=200
        )
        response = _agent().get("https://api.skyscanner.test/flights")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


# ---------------------------------------------------------------------------
# 2. MUDRAID_BASE_URL transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://api.mudraid.ai",
        "http://10.0.0.5:8001",
        "http://127.0.0.1.attacker.test",  # NOT loopback, despite the prefix
        "http://[2001:db8::1]:8001",
    ],
)
def test_cleartext_base_url_to_a_remote_host_is_refused(url: str) -> None:
    with pytest.raises(MudraIDConfigError, match="cleartext"):
        load_config(api_key_id="k", secret="s", base_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "http://127.9.9.9:8001",  # all of 127.0.0.0/8 is loopback
        "http://[::1]:8001",
    ],
)
def test_cleartext_to_loopback_is_permitted_for_local_development(url: str) -> None:
    config = load_config(api_key_id="k", secret="s", base_url=url)
    assert config.base_url == url


@pytest.mark.parametrize(
    "url", ["ftp://api.mudraid.ai", "file:///etc/passwd", "api.mudraid.ai", "https://"]
)
def test_a_url_that_is_not_an_absolute_http_url_is_refused(url: str) -> None:
    with pytest.raises(MudraIDConfigError):
        load_config(api_key_id="k", secret="s", base_url=url)


def test_the_rule_applies_to_the_env_var_not_only_the_kwarg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deployment sets this through the environment, which is the path that
    actually matters."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "k")
    monkeypatch.setenv("MUDRAID_SECRET", "s")
    monkeypatch.setenv("MUDRAID_BASE_URL", "http://api.mudraid.ai")
    with pytest.raises(MudraIDConfigError, match="cleartext"):
        load_config()


def test_https_and_the_production_default_are_accepted() -> None:
    assert load_config(api_key_id="k", secret="s").base_url == "https://api.mudraid.ai"
    assert (
        load_config(api_key_id="k", secret="s", base_url="https://eu.mudraid.ai/").base_url
        == "https://eu.mudraid.ai"
    )


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


@pytest.mark.parametrize("algorithm", ["RS256", "PS384", "ES256", "EdDSA"])
def test_asymmetric_algorithms_are_accepted(algorithm: str) -> None:
    signer = PyJWTSigner("key-material", kid="k1", algorithm=algorithm)
    assert signer._algorithm == algorithm  # noqa: SLF001 - asserting the stored choice


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
