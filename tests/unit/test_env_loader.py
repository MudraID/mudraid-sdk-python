"""M4.2 — env loader + Agent constructor wiring.

The fixture below clears the three MUDRAID_* env vars and the dotenv
load flag before each test, so no test ever inherits config from
another. We also point the cwd at a tmp dir per test to keep
``load_dotenv()`` from picking up the repo's actual ``.env`` (which
exists and contains real backend secrets).
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from mudraid import Agent, MudraIDConfigError
from mudraid._env import DEFAULT_BASE_URL, load_config


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Strip MudraID env vars and reset the dotenv load flag.

    Every test starts from a clean slate so explicit `monkeypatch.setenv`
    calls inside the test are the only source of truth for credential
    presence. Without this fixture a test could see leftover state from
    the previous case or — worse — from the developer's real .env.
    """
    for key in ("MUDRAID_API_KEY_ID", "MUDRAID_SECRET", "MUDRAID_BASE_URL"):
        monkeypatch.delenv(key, raising=False)

    # Force re-discovery of .env for every test (the loader caches on a
    # module-level flag for production efficiency).
    import mudraid._env as env_module

    monkeypatch.setattr(env_module, "_dotenv_loaded", False)

    monkeypatch.chdir(tmp_path)
    yield tmp_path


def test_explicit_kwargs_resolve_into_sdk_config() -> None:
    config = load_config(api_key_id="muid_kid_explicit", secret="muid_sk_explicit")
    assert config.api_key_id == "muid_kid_explicit"
    assert config.secret == "muid_sk_explicit"
    assert config.base_url == DEFAULT_BASE_URL


def test_credentials_loaded_from_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_from_env")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_from_env")

    config = load_config()
    assert config.api_key_id == "muid_kid_from_env"
    assert config.secret == "muid_sk_from_env"


def test_credentials_loaded_from_dotenv_file(isolated_env: Path) -> None:
    (isolated_env / ".env").write_text(
        "MUDRAID_API_KEY_ID=muid_kid_from_dotenv\n"
        "MUDRAID_SECRET=muid_sk_from_dotenv\n"
    )

    config = load_config()
    assert config.api_key_id == "muid_kid_from_dotenv"
    assert config.secret == "muid_sk_from_dotenv"


def test_explicit_kwargs_override_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact policy: caller-supplied kwargs win over env. This locks
    in the precedence so a future contributor can't quietly invert it."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_from_env")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_from_env")

    config = load_config(api_key_id="muid_kid_explicit", secret="muid_sk_explicit")
    assert config.api_key_id == "muid_kid_explicit"
    assert config.secret == "muid_sk_explicit"


def test_os_environ_overrides_dotenv_file(
    isolated_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Container env / CI must beat a stale local .env. Without this the
    SDK could silently send the wrong credentials in production."""
    (isolated_env / ".env").write_text(
        "MUDRAID_API_KEY_ID=muid_kid_stale_dotenv\n"
        "MUDRAID_SECRET=muid_sk_stale_dotenv\n"
    )
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_real_env")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_real_env")

    config = load_config()
    assert config.api_key_id == "muid_kid_real_env"
    assert config.secret == "muid_sk_real_env"


def test_missing_both_credentials_raises_with_both_names_listed() -> None:
    with pytest.raises(MudraIDConfigError) as exc:
        load_config()
    msg = str(exc.value)
    assert "MUDRAID_API_KEY_ID" in msg
    assert "MUDRAID_SECRET" in msg


def test_missing_only_secret_names_only_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_present")

    with pytest.raises(MudraIDConfigError) as exc:
        load_config()
    msg = str(exc.value)
    assert "MUDRAID_SECRET" in msg
    assert "MUDRAID_API_KEY_ID" not in msg


def test_whitespace_only_credential_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value of "   " in .env is a misconfiguration; treat it the same
    as missing so we don't ship blank credentials to MudraID and confuse
    the audit log."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "   ")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_present")

    with pytest.raises(MudraIDConfigError) as exc:
        load_config()
    assert "MUDRAID_API_KEY_ID" in str(exc.value)


def test_base_url_default_is_production_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "x")
    monkeypatch.setenv("MUDRAID_SECRET", "y")

    config = load_config()
    assert config.base_url == DEFAULT_BASE_URL


def test_base_url_overridable_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "x")
    monkeypatch.setenv("MUDRAID_SECRET", "y")
    monkeypatch.setenv("MUDRAID_BASE_URL", "http://localhost:8000")

    config = load_config()
    assert config.base_url == "http://localhost:8000"


def test_base_url_trailing_slash_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Internal HTTP code joins with f-strings like `{base_url}/api/v1/...`,
    so a stray trailing slash would produce `//api/v1/...`. Normalising
    here keeps the joining code obvious."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "x")
    monkeypatch.setenv("MUDRAID_SECRET", "y")
    monkeypatch.setenv("MUDRAID_BASE_URL", "https://api.mudraid.ai///")

    config = load_config()
    assert config.base_url == "https://api.mudraid.ai"


def test_sdk_config_is_frozen() -> None:
    config = load_config(api_key_id="x", secret="y")
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        config.api_key_id = "evil"  # type: ignore[misc]


# ---- Agent constructor integration ---------------------------------------


def test_agent_constructs_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_env_test")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_env_test")

    agent = Agent()
    assert agent.api_key_id == "muid_kid_env_test"
    assert agent.base_url == DEFAULT_BASE_URL


def test_agent_constructs_from_explicit_kwargs() -> None:
    agent = Agent(api_key_id="muid_kid_kw", secret="muid_sk_kw")
    assert agent.api_key_id == "muid_kid_kw"


def test_agent_construction_without_any_credentials_raises() -> None:
    with pytest.raises(MudraIDConfigError):
        Agent()


def test_agent_does_not_expose_secret_via_attribute() -> None:
    """The secret must never leak via a public property — only internal
    SDK modules access it through `_config.secret`. Locking this in
    so a well-meaning refactor can't accidentally expose it."""
    agent = Agent(api_key_id="x", secret="muid_sk_must_not_leak")

    public_attrs = [a for a in dir(agent) if not a.startswith("_")]
    for attr in public_attrs:
        value = getattr(agent, attr, None)
        if isinstance(value, str):
            assert "muid_sk_must_not_leak" not in value, (
                f"Secret leaked via public attribute `{attr}` — "
                f"only the internal `_config` is allowed to hold it."
            )


# ---- an unconfigured base URL is reported as configuration ---------------


def test_load_config_records_whether_the_base_url_was_defaulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-launch scan SSC-17 — the fact that drives the transport message."""
    assert load_config(api_key_id="x", secret="y").base_url_defaulted is True
    assert (
        load_config(api_key_id="x", secret="y", base_url=DEFAULT_BASE_URL).base_url_defaulted
        is False
    )
    monkeypatch.setenv("MUDRAID_BASE_URL", "https://api.staging.mudraid.test")
    assert load_config(api_key_id="x", secret="y").base_url_defaulted is False


def test_a_transport_failure_against_the_default_host_names_the_setting() -> None:
    """Pre-launch scan SSC-17 — an integrator who omitted MUDRAID_BASE_URL is
    told the base URL must be set, and where to get it, instead of a DNS
    failure the docs describe as possibly transient."""
    import requests
    import responses

    from mudraid import MudraIDNetworkError

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(
            responses.POST,
            f"{DEFAULT_BASE_URL}/api/v1/auth/agents/me/platforms",
            body=requests.exceptions.ConnectionError("name resolution failed"),
        )
        agent = Agent(api_key_id="muid_kid_x", secret="muid_sk_y")
        with pytest.raises(MudraIDNetworkError) as exc:
            agent.get("https://api.example.test/things")
    message = str(exc.value)
    assert "MUDRAID_BASE_URL is not set" in message
    assert "credential screen" in message
    assert DEFAULT_BASE_URL in message


def test_a_transport_failure_against_an_explicit_base_url_does_not_blame_the_setting() -> None:
    """The same host chosen deliberately is not second-guessed."""
    import requests
    import responses

    from mudraid import MudraIDNetworkError

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(
            responses.POST,
            f"{DEFAULT_BASE_URL}/api/v1/auth/agents/me/platforms",
            body=requests.exceptions.ConnectionError("name resolution failed"),
        )
        agent = Agent(api_key_id="muid_kid_x", secret="muid_sk_y", base_url=DEFAULT_BASE_URL)
        with pytest.raises(MudraIDNetworkError) as exc:
            agent.get("https://api.example.test/things")
    assert "MUDRAID_BASE_URL is not set" not in str(exc.value)
