"""M4.8 — logging guards: secrets and JWTs must never appear in logs.

The headline test runs a *full* SDK flow (Agent init → bootstrap →
token mint → platform call → 401 → refresh → retry) at the maximum
``DEBUG`` verbosity, captures every log record, and asserts the
captured stream contains:

  - none of the agent's plaintext secret
  - none of the issued JWT values
  - no full Authorization header

The rest of the file covers narrower guarantees per module.

If a future contributor adds a ``logger.debug("body=%s", body)``
somewhere along the credential path, one of these tests will catch
it before the leak reaches a customer's stdout.
"""

from __future__ import annotations

import logging
from typing import Iterator

import pytest
import responses

from mudraid import Agent

# The sentinels are deliberately distinctive so an accidental
# substring match on something like "muid_kid_test" won't pass the
# leak check. They are NOT real credentials.
_SECRET_VALUE = "muid_sk_LOG_LEAK_CANARY_zzzzzzzzzzzz"
_API_KEY_ID = "muid_kid_LOG_LEAK_CANARY_aaaaaaaaa"
_JWT_OLD = "JWT-OLD-pyq8r-CANARY-VALUE-zzzzzz.yyyyyy.xxxxxx"
_JWT_NEW = "JWT-NEW-pqr12-CANARY-VALUE-aaaaaa.bbbbbb.cccccc"

MUDRAID_BASE = "https://api.mudraid.test"
PLATFORMS_URL = f"{MUDRAID_BASE}/api/v1/auth/agents/me/platforms"
TOKEN_URL = f"{MUDRAID_BASE}/api/v1/auth/token"
PLATFORM_HOST = "api.platform.test"
PLATFORM_ID = "plt-1"
PLATFORM_URL = f"https://{PLATFORM_HOST}/x"


def _agent() -> Agent:
    return Agent(
        api_key_id=_API_KEY_ID,
        secret=_SECRET_VALUE,
        base_url=MUDRAID_BASE,
    )


def _stub_bootstrap(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={
            "agent_id": "agent-1",
            "platforms": [
                {
                    "platform_id": PLATFORM_ID,
                    "granted_scopes": ["x:y"],
                    "status": "active",
                    "name": "P",
                    "hostname": PLATFORM_HOST,
                    "verification_status": "verified",
                }
            ],
        },
        status=200,
    )


def _stub_token(rsps: responses.RequestsMock, jwt: str) -> None:
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": jwt, "token_type": "Bearer", "expires_in": 900},
        status=200,
    )


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


@pytest.fixture
def captured_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Capture every ``mudraid.*`` log record at DEBUG level."""
    caplog.set_level(logging.DEBUG, logger="mudraid")
    return caplog


def _everything_logged(caplog: pytest.LogCaptureFixture) -> str:
    """Concatenate every captured log message and structured arg into
    one string. Using the formatted record plus ``record.args`` covers
    the case where a future contributor logs the secret as a separate
    arg (``logger.debug("foo=%s", secret)``) — the formatted output
    contains the substituted value, and we also scan the unsubstituted
    args dict just to be safe."""
    parts: list[str] = []
    for record in caplog.records:
        parts.append(record.getMessage())
        if record.args:
            if isinstance(record.args, dict):
                parts.extend(str(v) for v in record.args.values())
            elif isinstance(record.args, tuple):
                parts.extend(str(v) for v in record.args)
            else:
                parts.append(str(record.args))
    return "\n".join(parts)


# ---- the headline guarantee ----------------------------------------------


def test_full_flow_at_debug_never_logs_secret_or_jwt(
    rsps: responses.RequestsMock,
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """End-to-end at DEBUG: every credential-bearing path runs, and
    the captured log stream contains nothing it shouldn't."""
    _stub_bootstrap(rsps)
    _stub_token(rsps, _JWT_OLD)
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, _JWT_NEW)
    rsps.add(responses.GET, PLATFORM_URL, json={"ok": True}, status=200)

    agent = _agent()
    agent.get(PLATFORM_URL)  # triggers bootstrap + mint + 401 + refresh + retry
    agent.refresh_platforms()
    agent.close()

    blob = _everything_logged(captured_logs)
    assert _SECRET_VALUE not in blob, "agent secret leaked into logs"
    assert _JWT_OLD not in blob, "JWT (old) leaked into logs"
    assert _JWT_NEW not in blob, "JWT (new) leaked into logs"
    assert f"Bearer {_JWT_OLD}" not in blob
    assert f"Bearer {_JWT_NEW}" not in blob


def test_secret_does_not_appear_in_logs_on_credential_failure(
    rsps: responses.RequestsMock,
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """Failure paths are the *most* tempting place to dump diagnostics
    that include the request body. The 401-from-MudraID flow exercises
    the exception path inside MudraIDHttpClient — assert it stays clean."""
    rsps.add(
        responses.POST,
        TOKEN_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )
    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )

    # The bootstrap will be tried first; force the failure that exercises
    # MudraIDHttpClient's exception-raising path.
    from mudraid import MudraIDAuthError

    with pytest.raises(MudraIDAuthError):
        _agent().get(PLATFORM_URL)

    blob = _everything_logged(captured_logs)
    assert _SECRET_VALUE not in blob


def test_secret_does_not_appear_in_logs_on_network_failure(
    rsps: responses.RequestsMock,
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """Connection errors carry the URL but must NOT carry the request body."""
    import requests as _requests

    rsps.add(
        responses.POST,
        PLATFORMS_URL,
        body=_requests.exceptions.ConnectionError("boom"),
    )

    from mudraid import MudraIDNetworkError

    with pytest.raises(MudraIDNetworkError):
        _agent().get(PLATFORM_URL)

    blob = _everything_logged(captured_logs)
    assert _SECRET_VALUE not in blob


# ---- positive signal: useful events ARE logged --------------------------


def test_logger_emits_useful_lifecycle_signals(
    rsps: responses.RequestsMock,
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """Anti-leak guarantees are only one half of the contract. The
    SDK must also actually emit enough signal at INFO that an operator
    can answer 'is the SDK working?' from logs alone — without dropping
    to DEBUG."""
    captured_logs.set_level(logging.INFO, logger="mudraid")
    _stub_bootstrap(rsps)
    _stub_token(rsps, _JWT_OLD)
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=200)

    _agent().get(PLATFORM_URL)

    blob = _everything_logged(captured_logs)
    # Agent construction announced (with the *public* api_key_id only).
    assert _API_KEY_ID in blob
    assert "Agent created" in blob
    # Bootstrap and mint happened.
    assert "bootstrapping" in blob.lower()
    assert "minting" in blob.lower()


def test_401_retry_logs_a_warning(
    rsps: responses.RequestsMock,
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """The retry path is *interesting* operationally — running a
    persistent stream of 401-then-200 cycles probably means a clock
    or rotation issue. Surface that at WARNING so log aggregators
    flag it."""
    captured_logs.set_level(logging.WARNING, logger="mudraid")
    _stub_bootstrap(rsps)
    _stub_token(rsps, _JWT_OLD)
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=401)
    _stub_token(rsps, _JWT_NEW)
    rsps.add(responses.GET, PLATFORM_URL, json={}, status=200)

    _agent().get(PLATFORM_URL)

    # At least one WARNING-level record about the 401 retry.
    warnings = [r for r in captured_logs.records if r.levelno == logging.WARNING]
    assert any(
        "401" in r.getMessage() for r in warnings
    ), f"Expected a 401-retry warning, got: {[r.getMessage() for r in warnings]}"


# ---- structured-args-leak guard ------------------------------------------


def test_logger_calls_use_safe_substitution_not_format(
    captured_logs: pytest.LogCaptureFixture,
) -> None:
    """A regression test for a future contributor who reaches for
    f-strings inside logger calls. ``logger.debug(f"secret={secret}")``
    eagerly formats; if it ever ships, the secret will appear in
    captured records via either ``record.msg`` or ``record.args``.
    This test runs the env loader (the simplest credential-bearing
    code path) and asserts no record CONTAINS the secret in either
    field — even when the record is itself constructed with safe
    args, just to lock the format pattern in."""
    from mudraid._env import load_config

    captured_logs.set_level(logging.DEBUG, logger="mudraid")

    load_config(api_key_id="muid_kid_sentinel", secret=_SECRET_VALUE)

    for record in captured_logs.records:
        assert _SECRET_VALUE not in record.getMessage()
        if record.args:
            args_view = (
                record.args.values()
                if isinstance(record.args, dict)
                else record.args
                if isinstance(record.args, tuple)
                else (record.args,)
            )
            for value in args_view:
                assert _SECRET_VALUE not in str(value)
