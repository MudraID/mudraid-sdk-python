"""Client-secret OAuth shares resource grants and safe HTTP behavior with signing."""

import base64
import logging
from urllib.parse import parse_qs

import pytest
import responses

from mudraid import (
    Agent,
    ClientSecretIdentity,
    MudraIDAuthError,
    MudraIDConfigError,
    MudraIDNetworkError,
    RequestedScopes,
)

ENDPOINT = "https://identity.example.test/oauth2/token"
RESOURCE = "https://api.example.test"
SECRET = "secret-canary-123"


def identity(**overrides):
    values = dict(
        client_id="client-one",
        token_endpoint=ENDPOINT,
        resource=RESOURCE,
        client_secret=SECRET,
        scopes=RequestedScopes.of(["tasks:read"]),
    )
    return ClientSecretIdentity(**(values | overrides))


def test_basic_credential_stays_at_token_endpoint_and_token_is_reused(caplog):
    caplog.set_level(logging.DEBUG, logger="mudraid")
    with responses.RequestsMock() as mock:
        mock.post(ENDPOINT, json={"access_token": "access-canary", "expires_in": 300})
        mock.get(RESOURCE + "/tasks", json=[])
        agent = Agent(identity())
        try:
            agent.get(RESOURCE + "/tasks")
            agent.get(RESOURCE + "/tasks")
        finally:
            agent.close()
        assert len(mock.calls) == 3
        token_request = mock.calls[0].request
        basic = base64.b64encode(f"client-one:{SECRET}".encode()).decode()
        assert token_request.headers["Authorization"] == f"Basic {basic}"
        assert parse_qs(token_request.body) == {
            "grant_type": ["client_credentials"],
            "resource": [RESOURCE],
            "scope": ["tasks:read"],
        }
        for call in mock.calls[1:]:
            assert call.request.headers["Authorization"] == "Bearer access-canary"
            assert SECRET not in str(call.request.body)
        assert SECRET not in repr(identity())
        for credential in [SECRET, basic, "access-canary"]:
            assert credential not in caplog.text


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_never_receives_basic_credentials(status):
    with responses.RequestsMock() as mock:
        mock.post(ENDPOINT, status=status, headers={"Location": "https://other.example/token"})
        agent = Agent(identity())
        try:
            with pytest.raises(MudraIDNetworkError):
                agent.get(RESOURCE)
        finally:
            agent.close()
        assert len(mock.calls) == 1


def test_authentication_failure_does_not_switch_methods():
    with responses.RequestsMock() as mock:
        mock.post(ENDPOINT, status=401, json={"error": "invalid_client"})
        agent = Agent(identity())
        try:
            with pytest.raises(MudraIDAuthError):
                agent.get(RESOURCE)
        finally:
            agent.close()
        assert len(mock.calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_secret", ""),
        ("client_id", ""),
        ("resource", ""),
        ("client_id", "bad:id"),
        ("token_endpoint", "http://remote.example/token"),
    ],
)
def test_bad_configuration_fails_locally(field, value):
    with pytest.raises(MudraIDConfigError):
        identity(**{field: value})


def test_explicit_secret_environment_needs_no_key_or_assertion_audience(monkeypatch):
    for key, value in {
        "CLIENT_ID": "client-one",
        "TOKEN_ENDPOINT": ENDPOINT,
        "RESOURCE": RESOURCE,
        "AUTH_METHOD": "client_secret_basic",
        "CLIENT_SECRET": SECRET,
    }.items():
        monkeypatch.setenv(f"BILLING_{key}", value)
    agent = Agent.from_env("BILLING")
    try:
        assert isinstance(agent._tokens._identity, ClientSecretIdentity)
        assert agent.resource == RESOURCE
    finally:
        agent.close()
    monkeypatch.delenv("BILLING_CLIENT_SECRET")
    monkeypatch.setenv("MUDRAID_CLIENT_SECRET", SECRET)
    with pytest.raises(MudraIDConfigError, match="BILLING_CLIENT_SECRET"):
        Agent.from_env("BILLING")


def test_unknown_auth_method_does_not_fall_back(monkeypatch):
    for key, value in {
        "CLIENT_ID": "client-one",
        "TOKEN_ENDPOINT": ENDPOINT,
        "RESOURCE": RESOURCE,
        "AUTH_METHOD": "automatic",
    }.items():
        monkeypatch.setenv(f"MUDRAID_{key}", value)
    with pytest.raises(MudraIDConfigError, match="AUTH_METHOD"):
        Agent.from_env()
