"""SDK 2's public default and migrated HTTP/lifecycle boundaries."""

import importlib.util
import logging
from unittest.mock import Mock
from urllib.parse import parse_qs

import pytest
import requests
import responses

from mudraid import Agent, MachineIdentity, MachineTokenManager, MudraIDConfigError

TOKEN = "https://identity.example.test/oauth2/token"
RESOURCE = "https://resource.example.test"


class Signer:
    def sign(self, claims):
        return "ASSERTION-CANARY"


def identity(client="client-one"):
    return MachineIdentity(
        client_id=client,
        token_endpoint=TOKEN,
        audience=TOKEN,
        resource=RESOURCE,
        signer=Signer(),
    )


@pytest.mark.parametrize("module", ["_agent", "_env", "_platform_resolver", "_token_manager"])
def test_native_implementations_are_not_shipped(module):
    assert importlib.util.find_spec(f"mudraid.{module}") is None


def test_native_credentials_cannot_construct_the_public_client(monkeypatch):
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "legacy-id")
    monkeypatch.setenv("MUDRAID_SECRET", "legacy-secret")
    monkeypatch.delenv("MUDRAID_CLIENT_ID", raising=False)
    with responses.RequestsMock() as mock:
        with pytest.raises(TypeError):
            Agent(api_key_id="legacy-id", secret="legacy-secret")
        with pytest.raises(MudraIDConfigError, match="MUDRAID_CLIENT_ID"):
            Agent.from_env()
        assert not mock.calls
    assert not hasattr(Agent, "legacy")
    assert not hasattr(Agent, "refresh_platforms")


@pytest.mark.parametrize("method", ["get", "head", "options", "post", "put", "patch", "delete"])
def test_every_http_method_uses_v2_and_preserves_request_headers(method, caplog):
    caplog.set_level(logging.DEBUG, logger="mudraid")
    agent = Agent(identity())
    with responses.RequestsMock() as mock:
        mock.add(responses.POST, TOKEN, json={"access_token": "ACCESS-CANARY", "expires_in": 300})
        mock.add(method.upper(), RESOURCE + "/tasks", status=204)
        try:
            result = getattr(agent, method)(
                RESOURCE + "/tasks", headers={"X-Trace": "trace"}, timeout=7
            )
            assert result.status_code == 204
            assert [c.request.url for c in mock.calls] == [TOKEN, RESOURCE + "/tasks"]
            assert parse_qs(mock.calls[0].request.body)["grant_type"] == ["client_credentials"]
            assert mock.calls[-1].request.headers["Authorization"] == "Bearer ACCESS-CANARY"
            assert mock.calls[-1].request.headers["X-Trace"] == "trace"
            assert "ASSERTION-CANARY" not in caplog.text
            assert "ACCESS-CANARY" not in caplog.text
        finally:
            agent.close()


def test_separate_clients_do_not_share_cached_tokens():
    first, second = Agent(identity("one")), Agent(identity("two"))
    with responses.RequestsMock() as mock:
        for token in ["token-one", "token-two"]:
            mock.add(responses.POST, TOKEN, json={"access_token": token, "expires_in": 300})
        mock.add(responses.GET, RESOURCE, status=204)
        try:
            first.get(RESOURCE)
            second.get(RESOURCE)
            first.get(RESOURCE)
            calls = [c for c in mock.calls if c.request.method == "GET"]
            assert [c.request.headers["Authorization"] for c in calls] == [
                "Bearer token-one",
                "Bearer token-two",
                "Bearer token-one",
            ]
            assert len([c for c in mock.calls if c.request.method == "POST"]) == 2
        finally:
            first.close()
            second.close()


def test_close_releases_both_owned_connection_pools(monkeypatch):
    sessions = []
    session_type = requests.Session

    def make_session():
        session = Mock(spec=session_type)
        sessions.append(session)
        return session

    monkeypatch.setattr(requests, "Session", make_session)
    agent = Agent(identity())
    agent.close()
    assert len(sessions) == 2
    for session in sessions:
        session.close.assert_called_once()


def test_supplied_manager_and_session_remain_caller_owned():
    session = Mock(spec=requests.Session)
    manager = MachineTokenManager(identity(), session=session)
    agent = Agent(identity(), token_manager=manager)
    agent.close()
    session.close.assert_not_called()
    manager.close()
    session.close.assert_not_called()


def test_concurrent_token_requests_share_one_mint():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    ready = Barrier(8)
    manager = MachineTokenManager(identity())
    with responses.RequestsMock() as mock:
        mock.add(responses.POST, TOKEN, json={"access_token": "shared", "expires_in": 300})

        def acquire():
            ready.wait(timeout=5)
            return manager.get_token()

        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(acquire) for _ in range(8)]
                assert [f.result(timeout=5) for f in futures] == ["shared"] * 8
            assert len(mock.calls) == 1
        finally:
            manager.close()


@pytest.mark.parametrize("failure", [401, 500, "transport"])
def test_credential_and_network_failures_do_not_log_secrets(failure, caplog):
    from contextlib import closing

    from mudraid import ClientSecretIdentity, MudraIDError

    caplog.set_level(logging.DEBUG, logger="mudraid")
    secret = "CLIENT-SECRET-FAILURE-CANARY"
    configured = ClientSecretIdentity(
        client_id="client-one", token_endpoint=TOKEN, resource=RESOURCE, client_secret=secret
    )
    with responses.RequestsMock() as mock, closing(Agent(configured)) as agent:
        if failure == "transport":
            mock.add(responses.POST, TOKEN, body=requests.ConnectionError("unreachable"))
        else:
            mock.add(responses.POST, TOKEN, status=failure, json={"error": "invalid_client"})
        with pytest.raises(MudraIDError) as caught:
            agent.get(RESOURCE)
        assert secret not in caplog.text
        assert secret not in str(caught.value)
        assert len(mock.calls) == 1
