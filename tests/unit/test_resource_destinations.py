"""Destination safety survives removal of native platform discovery."""

from contextlib import closing

import pytest
import responses

from mudraid import Agent, ClientSecretIdentity, MudraIDConfigError

TOKEN = "https://identity.example/token"
RESOURCE = "https://api.example/tasks"


def identity(resource=RESOURCE):
    return ClientSecretIdentity(
        client_id="client", client_secret="secret", token_endpoint=TOKEN, resource=resource
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/tasks",
        "https://api.example.attacker.example/tasks",
        "https://api.example@attacker.example/tasks",
        "https://api.example:444/tasks",
        "http://api.example/tasks",
        "https://api.example/\ntasks",
        "https://api.example/tasks#fragment",
        "//api.example/tasks",
        "https:///tasks",
    ],
)
def test_bad_destination_is_refused_before_mint_or_network(url):
    with responses.RequestsMock() as mock:
        with closing(Agent(identity())) as agent:
            with pytest.raises(MudraIDConfigError):
                agent.get(url)
        assert not mock.calls


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_resource_redirect_never_sends_a_second_request(status):
    with responses.RequestsMock() as mock:
        mock.post(TOKEN, json={"access_token": "access", "expires_in": 300})
        mock.post(RESOURCE, status=status, headers={"Location": "https://attacker.example/tasks"})
        with closing(Agent(identity())) as agent:
            assert agent.post(RESOURCE, json={"private": "payload"}).status_code == status
        assert len(mock.calls) == 2


def test_automatic_redirect_opt_in_is_refused_before_network():
    with responses.RequestsMock() as mock:
        with closing(Agent(identity())) as agent:
            with pytest.raises(MudraIDConfigError, match="redirects"):
                agent.get(RESOURCE, allow_redirects=True)
        assert not mock.calls


def test_explicit_origin_supports_non_url_resource_without_widening_authority():
    with responses.RequestsMock() as mock:
        mock.post(TOKEN, json={"access_token": "access", "expires_in": 300})
        mock.get(RESOURCE, status=200)
        with closing(
            Agent(identity("urn:example:tasks"), resource_origins=["https://api.example"])
        ) as agent:
            assert agent.get(RESOURCE).status_code == 200
            with pytest.raises(MudraIDConfigError):
                agent.get("https://other.example/tasks")
        assert "urn%3Aexample%3Atasks" in mock.calls[0].request.body
        assert len(mock.calls) == 2


def test_environment_origin_override_is_prefix_scoped(monkeypatch):
    for suffix, value in {
        "CLIENT_ID": "client",
        "CLIENT_SECRET": "secret",
        "AUTH_METHOD": "client_secret_basic",
        "TOKEN_ENDPOINT": TOKEN,
        "RESOURCE": "urn:example:tasks",
        "RESOURCE_ORIGINS": "https://api.example",
    }.items():
        monkeypatch.setenv(f"WORKER_{suffix}", value)
    monkeypatch.setenv("MUDRAID_RESOURCE_ORIGINS", "https://attacker.example")
    with responses.RequestsMock() as mock:
        with closing(Agent.from_env("WORKER")) as agent:
            with pytest.raises(MudraIDConfigError):
                agent.get("https://attacker.example/tasks")
        assert not mock.calls


def test_empty_allowlist_fails_closed():
    with pytest.raises(MudraIDConfigError):
        Agent(identity(), resource_origins=[])


@pytest.mark.parametrize(
    "origins",
    [None, "https://api.example", ["https://api.example/tasks"], ["https://api.example?x=1"]],
)
def test_origin_configuration_is_explicit(origins):
    with pytest.raises(MudraIDConfigError):
        Agent(identity("urn:example:tasks"), resource_origins=origins)


def test_https_default_port_and_hostname_case_are_equivalent():
    with responses.RequestsMock() as mock:
        mock.post(TOKEN, json={"access_token": "access", "expires_in": 300})
        mock.get("https://api.example:443/tasks", status=200)
        with closing(Agent(identity())) as agent:
            assert agent.get("https://API.EXAMPLE:443/tasks").status_code == 200
