"""Safety invariant: no blind replay of an ambiguous call.

The dangerous case: a consequential request (``POST``/``PATCH``) that was put on
the wire but never got a response (read timeout, mid-flight drop). The server may
already have processed it, so a retry could duplicate the action. The SDK must:

  * NOT retry it — surface :class:`mudraid.MudraIDExecutionUnknownError`;
  * UNLESS an idempotency key the server deduplicates is attached, or the method
    is idempotent, or the failure provably happened before the server saw the
    request (a connect timeout).

Part A unit-tests :func:`mudraid._consequence.execute` with a fake sender for
exact attempt counting. Part B drives the same guarantees end to end through
:class:`mudraid.MachineAgent` with mocked HTTP.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Iterator

import pytest
import requests
import responses

from mudraid import (
    IDEMPOTENCY_KEY_HEADER,
    MachineAgent,
    MachineIdentity,
    MudraIDExecutionUnknownError,
    RequestedScopes,
)
from mudraid._consequence import execute, is_idempotent

TOKEN_ENDPOINT = "https://identity.mudraid.test/oauth2/token"
RESOURCE_URL = "https://api.acme.test/charges"


# =========================================================================
# Part A — execute() with a fake sender (precise attempt counting)
# =========================================================================


class _FakeSender:
    """Fails the first N attempts with ``exc``, then returns a 200 response."""

    def __init__(self, exc: Exception | None, *, fail_times: int = 1) -> None:
        self.exc = exc
        self.fail_times = fail_times
        self.calls: list[dict[str, str]] = []

    def __call__(self, extra_headers: dict[str, str]) -> object:
        self.calls.append(dict(extra_headers))
        if self.exc is not None and len(self.calls) <= self.fail_times:
            raise self.exc
        return SimpleNamespace(status_code=200)


def test_ambiguous_consequential_without_key_is_not_replayed() -> None:
    """POST + read timeout (sent, no response) + no key ⇒ execution-unknown,
    and exactly ONE attempt was made (never replayed)."""
    sender = _FakeSender(requests.exceptions.ReadTimeout("no response"))
    with pytest.raises(MudraIDExecutionUnknownError):
        execute(sender, method="POST")
    assert len(sender.calls) == 1, "an ambiguous consequential call must not be retried"


def test_ambiguous_consequential_chains_the_transport_error() -> None:
    original = requests.exceptions.ReadTimeout("no response")
    sender = _FakeSender(original)
    with pytest.raises(MudraIDExecutionUnknownError) as exc:
        execute(sender, method="POST")
    assert exc.value.__cause__ is original


def test_connection_drop_on_consequential_is_ambiguous_not_replayed() -> None:
    """A bare ConnectionError (not a connect timeout) after send is ambiguous —
    conservatively treated as sent, so it is not replayed."""
    sender = _FakeSender(requests.exceptions.ConnectionError("dropped"))
    with pytest.raises(MudraIDExecutionUnknownError):
        execute(sender, method="PATCH")
    assert len(sender.calls) == 1


def test_pre_response_failure_is_safe_to_retry_even_for_consequential() -> None:
    """A connect timeout means the server never saw the request — the action
    never started — so retrying a POST is safe."""
    sender = _FakeSender(requests.exceptions.ConnectTimeout("never connected"))
    resp = execute(sender, method="POST")
    assert resp.status_code == 200
    assert len(sender.calls) == 2, "pre-response failures may be safely retried"


def test_idempotent_method_ambiguous_failure_is_retried() -> None:
    """GET is idempotent — replaying it cannot duplicate an effect — so an
    ambiguous read timeout is retried."""
    sender = _FakeSender(requests.exceptions.ReadTimeout("no response"))
    resp = execute(sender, method="GET")
    assert resp.status_code == 200
    assert len(sender.calls) == 2


def test_idempotency_key_makes_consequential_retry_safe_and_is_attached() -> None:
    """With a server-dedupable key, an ambiguous POST IS retried, and the key
    rides on every attempt so the server collapses the duplicate."""
    sender = _FakeSender(requests.exceptions.ReadTimeout("no response"))
    resp = execute(sender, method="POST", idempotency_key="idem-123")
    assert resp.status_code == 200
    assert len(sender.calls) == 2
    for attempt_headers in sender.calls:
        assert attempt_headers.get(IDEMPOTENCY_KEY_HEADER) == "idem-123"


def test_safe_retry_budget_exhausted_reraises_transport_error() -> None:
    """A GET that keeps timing out past the retry budget surfaces the original
    transport error (not execution-unknown — GET is not the dangerous case)."""
    sender = _FakeSender(requests.exceptions.ReadTimeout("still down"), fail_times=5)
    with pytest.raises(requests.exceptions.ReadTimeout):
        execute(sender, method="GET", max_retries=1)
    assert len(sender.calls) == 2  # first + one retry, then give up


def test_http_response_is_a_definite_outcome_and_returned() -> None:
    """Even a 500 is a definite outcome — execute returns it, never retries on
    status (status retry is a separate, caller-owned policy)."""
    sender = _FakeSender(None)

    def send_500(extra_headers: dict[str, str]) -> object:
        sender.calls.append(dict(extra_headers))
        return SimpleNamespace(status_code=500)

    resp = execute(send_500, method="POST")
    assert resp.status_code == 500
    assert len(sender.calls) == 1


def test_method_idempotency_classification() -> None:
    for m in ("GET", "HEAD", "OPTIONS", "PUT", "DELETE"):
        assert is_idempotent(m)
    for m in ("POST", "PATCH"):
        assert not is_idempotent(m)


# =========================================================================
# Part B — MachineAgent end to end (mocked HTTP)
# =========================================================================


class _FakeSigner:
    def sign(self, claims: object) -> str:
        return "SIGNED.ASSERTION"


def _identity() -> MachineIdentity:
    return MachineIdentity(
        client_id="mc_abc",
        token_endpoint=TOKEN_ENDPOINT,
        audience=TOKEN_ENDPOINT,
        resource="https://api.acme.test/",
        signer=_FakeSigner(),
        scopes=RequestedScopes.of(["charges:write"]),
    )


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


def _stub_token(rsps: responses.RequestsMock, access_token: str = "at-1") -> None:
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": 300},
        status=200,
    )


def _resource_calls(rsps: responses.RequestsMock) -> list[responses.Call]:
    return [c for c in rsps.calls if c.request.url.startswith(RESOURCE_URL)]


def test_machine_agent_post_ambiguous_failure_surfaces_execution_unknown(
    rsps: responses.RequestsMock,
) -> None:
    """End to end: a POST that times out mid-flight with no key is never
    replayed — the caller gets MudraIDExecutionUnknownError and the resource was
    contacted exactly once."""
    _stub_token(rsps)
    rsps.add(responses.POST, RESOURCE_URL, body=requests.exceptions.ReadTimeout("no response"))

    agent = MachineAgent(_identity())
    with pytest.raises(MudraIDExecutionUnknownError):
        agent.post(RESOURCE_URL, json={"amount": 100})
    assert len(_resource_calls(rsps)) == 1


def test_machine_agent_post_with_idempotency_key_is_retried_with_header(
    rsps: responses.RequestsMock,
) -> None:
    _stub_token(rsps)
    rsps.add(responses.POST, RESOURCE_URL, body=requests.exceptions.ReadTimeout("no response"))
    rsps.add(responses.POST, RESOURCE_URL, json={"ok": True}, status=200)

    agent = MachineAgent(_identity())
    resp = agent.post(RESOURCE_URL, json={"amount": 100}, idempotency_key="idem-xyz")

    assert resp.status_code == 200
    resource_calls = _resource_calls(rsps)
    assert len(resource_calls) == 2
    assert resource_calls[1].request.headers[IDEMPOTENCY_KEY_HEADER] == "idem-xyz"


def test_machine_agent_get_ambiguous_failure_is_retried(
    rsps: responses.RequestsMock,
) -> None:
    _stub_token(rsps)
    rsps.add(responses.GET, RESOURCE_URL, body=requests.exceptions.ReadTimeout("blip"))
    rsps.add(responses.GET, RESOURCE_URL, json={"ok": True}, status=200)

    agent = MachineAgent(_identity())
    resp = agent.get(RESOURCE_URL)
    assert resp.status_code == 200
    assert len(_resource_calls(rsps)) == 2


def test_machine_agent_get_attaches_bearer_token(rsps: responses.RequestsMock) -> None:
    _stub_token(rsps, access_token="at-bearer")
    rsps.add(responses.GET, RESOURCE_URL, json={"ok": True}, status=200)

    MachineAgent(_identity()).get(RESOURCE_URL)
    assert _resource_calls(rsps)[0].request.headers["Authorization"] == "Bearer at-bearer"


def test_machine_agent_401_on_get_refreshes_and_replays(
    rsps: responses.RequestsMock,
) -> None:
    _stub_token(rsps, access_token="at-old")
    rsps.add(responses.GET, RESOURCE_URL, json={}, status=401)
    _stub_token(rsps, access_token="at-new")
    rsps.add(responses.GET, RESOURCE_URL, json={"ok": True}, status=200)

    resp = MachineAgent(_identity()).get(RESOURCE_URL)
    assert resp.status_code == 200
    resource_calls = _resource_calls(rsps)
    assert resource_calls[0].request.headers["Authorization"] == "Bearer at-old"
    assert resource_calls[1].request.headers["Authorization"] == "Bearer at-new"


def test_machine_agent_401_on_consequential_post_without_key_is_not_replayed(
    rsps: responses.RequestsMock,
) -> None:
    """A 401 could arrive AFTER the server mutated state. For a consequential
    POST with no idempotency key we must NOT refresh-and-replay — that would
    duplicate the action. The original 401 is returned for the caller to handle;
    the resource is contacted exactly once."""
    _stub_token(rsps, access_token="at-old")
    rsps.add(responses.POST, RESOURCE_URL, json={"err": "expired"}, status=401)
    # A second resource response is registered but must NOT be consumed.
    rsps.add(responses.POST, RESOURCE_URL, json={"ok": True}, status=200)

    resp = MachineAgent(_identity()).post(RESOURCE_URL, json={"amount": 100})
    assert resp.status_code == 401
    assert len(_resource_calls(rsps)) == 1, "consequential 401 must not be replayed without a key"


def test_machine_agent_401_on_post_with_key_is_replayed(
    rsps: responses.RequestsMock,
) -> None:
    """With an idempotency key the server deduplicates, so a 401 refresh+replay
    of a consequential POST is safe and happens."""
    _stub_token(rsps, access_token="at-old")
    rsps.add(responses.POST, RESOURCE_URL, json={}, status=401)
    _stub_token(rsps, access_token="at-new")
    rsps.add(responses.POST, RESOURCE_URL, json={"ok": True}, status=200)

    resp = MachineAgent(_identity()).post(
        RESOURCE_URL, json={"amount": 100}, idempotency_key="idem-1"
    )
    assert resp.status_code == 200
    assert len(_resource_calls(rsps)) == 2
