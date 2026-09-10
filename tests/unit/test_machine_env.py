"""The supported V2 loader keeps identities and failure paths explicit."""

import json
from urllib.parse import parse_qs

import pytest
import responses

from mudraid import MachineAgent, MudraIDConfigError

TOKEN = "https://identity.example.test/oauth2/token"
RESOURCE = "https://tasks.example.test"


class Signer:
    def sign(self, claims):
        assert claims["iss"] == claims["sub"] == "client-worker"
        assert claims["aud"] == TOKEN
        return "test-signed-assertion"


@pytest.fixture
def configured(monkeypatch):
    for name, value in {
        "CLIENT_ID": "client-worker",
        "TOKEN_ENDPOINT": TOKEN,
        "ASSERTION_AUDIENCE": TOKEN,
        "RESOURCE": RESOURCE,
        "SCOPES": "tasks:read",
    }.items():
        monkeypatch.setenv(f"WORKER_{name}", value)


@pytest.mark.parametrize("name", ["CLIENT_ID", "TOKEN_ENDPOINT", "ASSERTION_AUDIENCE", "RESOURCE"])
@pytest.mark.parametrize("value", [None, "   "])
def test_missing_identity_never_falls_back(configured, monkeypatch, name, value):
    monkeypatch.setenv(f"MUDRAID_{name}", "another-identity")
    monkeypatch.setenv("WORKER_API_KEY_ID", "legacy-key")
    monkeypatch.setenv("WORKER_SECRET", "legacy-secret")
    if value is None:
        monkeypatch.delenv(f"WORKER_{name}")
    else:
        monkeypatch.setenv(f"WORKER_{name}", value)
    with responses.RequestsMock() as mock:
        with pytest.raises(MudraIDConfigError, match=f"WORKER_{name}"):
            MachineAgent.from_env("WORKER", signer=Signer())
        assert not mock.calls


@pytest.mark.parametrize("prefix", ["", "bad prefix", "bad-prefix", "1WORKER", None])
def test_invalid_prefix_is_rejected(prefix):
    with pytest.raises(MudraIDConfigError, match="prefix"):
        MachineAgent.from_env(prefix, signer=Signer())


@pytest.mark.parametrize("scopes", [None, "", "tasks:read tasks:write"])
def test_custom_signer_needs_no_key_file_and_omission_never_broadens(
    configured, monkeypatch, scopes
):
    if scopes is None:
        monkeypatch.delenv("WORKER_SCOPES")
    else:
        monkeypatch.setenv("WORKER_SCOPES", scopes)
    monkeypatch.setenv("WORKER_PRIVATE_KEY_PATH", "/must/not/be/opened")
    with responses.RequestsMock() as mock:
        agent = MachineAgent.from_env("WORKER", signer=Signer())
        assert not mock.calls

        def mint(request):
            form = parse_qs(request.body)
            assert form["grant_type"] == ["client_credentials"]
            assert form["resource"] == [RESOURCE]
            assert form["client_assertion"] == ["test-signed-assertion"]
            if scopes:
                assert set(form["scope"][0].split()) == set(scopes.split())
            else:
                assert "scope" not in form
            assert "secret" not in form and "api_key_id" not in form
            return 200, {}, json.dumps({"access_token": "test-access", "expires_in": 300})

        mock.add_callback(responses.POST, TOKEN, callback=mint)
        mock.add(responses.GET, RESOURCE + "/tasks", json={"tasks": []})
        try:
            assert agent.get(RESOURCE + "/tasks").status_code == 200
            assert [call.request.url for call in mock.calls] == [TOKEN, RESOURCE + "/tasks"]
        finally:
            agent.close()


def test_dotenv_is_not_discovered(configured, monkeypatch, tmp_path):
    monkeypatch.delenv("WORKER_CLIENT_ID")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("WORKER_CLIENT_ID=hidden-fallback\n")
    with pytest.raises(MudraIDConfigError, match="WORKER_CLIENT_ID"):
        MachineAgent.from_env("WORKER", signer=Signer())


@pytest.mark.parametrize("name", ["PRIVATE_KEY_PATH", "KEY_ID"])
def test_builtin_signer_requires_explicit_key_configuration(configured, monkeypatch, name):
    monkeypatch.setenv("WORKER_PRIVATE_KEY_PATH", "/not/opened")
    monkeypatch.setenv("WORKER_KEY_ID", "registered-kid")
    monkeypatch.delenv(f"WORKER_{name}")
    with pytest.raises(MudraIDConfigError, match=f"WORKER_{name}"):
        MachineAgent.from_env("WORKER")


@pytest.mark.parametrize("path", ["private-value-that-must-not-appear", "invalid\x00path"])
def test_key_read_error_does_not_expose_configured_value(configured, monkeypatch, path):
    monkeypatch.setenv("WORKER_PRIVATE_KEY_PATH", path) if "\x00" not in path else None
    # os.environ cannot contain NUL, but its mapping can be supplied by a host
    # or embedded runtime. Exercise the path-error renderer independently.
    if "\x00" in path:
        monkeypatch.setattr(
            "mudraid._machine_env.os.environ",
            {
                "WORKER_CLIENT_ID": "client-worker",
                "WORKER_TOKEN_ENDPOINT": TOKEN,
                "WORKER_ASSERTION_AUDIENCE": TOKEN,
                "WORKER_RESOURCE": RESOURCE,
                "WORKER_KEY_ID": "registered-kid",
                "WORKER_PRIVATE_KEY_PATH": path,
            },
        )
    else:
        monkeypatch.setenv("WORKER_KEY_ID", "registered-kid")
    with pytest.raises(MudraIDConfigError) as caught:
        MachineAgent.from_env("WORKER")
    assert "WORKER_PRIVATE_KEY_PATH" in str(caught.value)
    assert path not in str(caught.value)
    assert caught.value.__suppress_context__


def test_empty_key_file_is_rejected(configured, monkeypatch, tmp_path):
    key = tmp_path / "empty.pem"
    key.write_text(" \n")
    monkeypatch.setenv("WORKER_PRIVATE_KEY_PATH", str(key))
    monkeypatch.setenv("WORKER_KEY_ID", "registered-kid")
    with pytest.raises(MudraIDConfigError, match="is empty"):
        MachineAgent.from_env("WORKER")
