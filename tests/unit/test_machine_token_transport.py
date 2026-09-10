"""V2 client assertions must never be sent to a remote cleartext endpoint."""

import pytest
import responses

from mudraid import MachineAgent, MachineIdentity, MudraIDConfigError


class NeverSign:
    def sign(self, claims):
        pytest.fail("invalid token endpoint reached the signer")


def identity(endpoint):
    return MachineIdentity(
        client_id="test-client",
        token_endpoint=endpoint,
        audience="https://identity.example.test/oauth2/token",
        resource="https://resource.example.test",
        signer=NeverSign(),
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://identity.example.test/oauth2/token",
        "http://192.168.1.1/oauth2/token",
        "http://localhost.example.test/oauth2/token",
        "//identity.example.test/oauth2/token",
        "ftp://identity.example.test/token",
        "https:///oauth2/token",
        "https://identity.example.test:invalid/token",
        "https://identity.example.test:99999/token",
        "https://identity.example.test/token#fragment",
        "https://private-user:private-password@identity.example.test/token",
        "https://identity.example.test/\ntoken",
        "https://identity.example.test/token with spaces",
        "https://[broken-ipv6/token",
    ],
)
def test_bad_endpoint_is_refused_before_signing_or_network(endpoint):
    with responses.RequestsMock() as mock:
        with pytest.raises(MudraIDConfigError) as caught:
            identity(endpoint)
        assert endpoint not in str(caught.value)
        assert "private-password" not in str(caught.value)
        assert not mock.calls


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://identity.example.test/oauth2/token",
        "https://identity.example.test:8443/oauth2/token?tenant=test",
        "http://localhost:8000/oauth2/token",
        "http://127.0.0.1:8000/oauth2/token",
        "http://[::1]:8000/oauth2/token",
    ],
)
def test_https_and_explicit_loopback_development_are_allowed(endpoint):
    assert identity(endpoint).token_endpoint == endpoint


def test_environment_loader_cannot_bypass_transport_policy(monkeypatch):
    for name, value in {
        "CLIENT_ID": "test-client",
        "TOKEN_ENDPOINT": "http://remote.example.test/oauth2/token",
        "ASSERTION_AUDIENCE": "https://identity.example.test/oauth2/token",
        "RESOURCE": "https://resource.example.test",
    }.items():
        monkeypatch.setenv(f"WORKER_{name}", value)
    with pytest.raises(MudraIDConfigError):
        MachineAgent.from_env("WORKER", signer=NeverSign())
