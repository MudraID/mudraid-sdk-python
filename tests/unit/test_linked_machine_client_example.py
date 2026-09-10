"""KAN-176: the shipped example uses V2 without legacy discovery or fallback."""

import json
import runpy
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import responses

from mudraid import (
    Agent,
    MudraIDConfigError,
    MudraIDPlatformNotRegisteredError,
    MudraIDRevokedError,
)

TOKEN = "https://identity.example.test/oauth2/token"
RESOURCE = "https://tasks.example.test"


@pytest.fixture
def configured(tmp_path, monkeypatch):
    pytest.importorskip("jwt", reason="the [v2] extra is not installed")
    pytest.importorskip("cryptography", reason="the [v2] extra is not installed")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "private.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    values = {
        "CLIENT_ID": "test-linked-client",
        "PRIVATE_KEY_PATH": str(path),
        "KEY_ID": "registered-kid",
        "TOKEN_ENDPOINT": TOKEN,
        "ASSERTION_AUDIENCE": TOKEN,
        "RESOURCE": RESOURCE,
        "SCOPES": "tasks:read",
    }
    for name, value in values.items():
        monkeypatch.setenv(f"WEBSITE_API_{name}", value)
    example = Path(__file__).resolve().parents[2] / "examples/linked_machine_client.py"
    return runpy.run_path(str(example))["build_agent"], key


def test_linked_client_example_signs_and_calls_without_legacy_discovery(configured):
    import jwt

    build_agent, key = configured
    agent = build_agent("WEBSITE_API")
    with responses.RequestsMock() as mock:

        def mint(request):
            form = parse_qs(request.body)
            assert form["grant_type"] == ["client_credentials"]
            assert form["resource"] == [RESOURCE]
            assert form["scope"] == ["tasks:read"]
            assertion = form["client_assertion"][0]
            claims = jwt.decode(assertion, key.public_key(), algorithms=["RS256"], audience=TOKEN)
            assert claims["iss"] == claims["sub"] == "test-linked-client"
            assert jwt.get_unverified_header(assertion)["kid"] == "registered-kid"
            return (
                200,
                {},
                json.dumps(
                    {"access_token": "test-access", "token_type": "Bearer", "expires_in": 300}
                ),
            )

        mock.add_callback(responses.POST, TOKEN, callback=mint)
        mock.add(responses.GET, RESOURCE + "/tasks", json={"tasks": []})
        try:
            assert agent.get(RESOURCE + "/tasks", timeout=15).status_code == 200
            assert [c.request.url for c in mock.calls] == [TOKEN, RESOURCE + "/tasks"]
            assert mock.calls[-1].request.headers["Authorization"] == "Bearer test-access"
        finally:
            agent.close()


def test_missing_v2_configuration_does_not_use_legacy_credentials(configured, monkeypatch):
    build_agent, _ = configured
    monkeypatch.delenv("WEBSITE_API_CLIENT_ID")
    monkeypatch.setenv("WEBSITE_API_API_KEY_ID", "test-legacy-id")
    monkeypatch.setenv("WEBSITE_API_SECRET", "test-legacy-secret")
    with responses.RequestsMock() as mock:
        with pytest.raises(MudraIDConfigError, match="WEBSITE_API_CLIENT_ID"):
            build_agent("WEBSITE_API")
        assert not mock.calls


def test_token_refusal_does_not_call_platform_or_fall_back(configured):
    build_agent, _ = configured
    agent = build_agent("WEBSITE_API")
    with responses.RequestsMock() as mock:
        mock.add(responses.POST, TOKEN, status=400, json={"error": "invalid_grant"})
        try:
            with pytest.raises(MudraIDRevokedError):
                agent.get(RESOURCE + "/tasks", timeout=15)
            assert [c.request.url for c in mock.calls] == [TOKEN]
        finally:
            agent.close()


def test_legacy_empty_discovery_explains_linked_client_path():
    agent = Agent(
        api_key_id="test-legacy-id",
        secret="test-legacy-secret",
        base_url="https://identity.example.test",
    )
    with responses.RequestsMock() as mock:
        mock.add(
            responses.POST,
            "https://identity.example.test/api/v1/auth/agents/me/platforms",
            json={"platforms": []},
        )
        try:
            with pytest.raises(MudraIDPlatformNotRegisteredError) as caught:
                agent.get(RESOURCE + "/tasks")
            message = str(caught.value)
            assert "legacy Agent profile" in message
            assert "MachineAgent with MachineIdentity" in message
            assert "test-legacy-secret" not in message
            assert len(mock.calls) == 1
        finally:
            agent.close()
