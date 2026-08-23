"""KAN-90 — per-agent credential prefixes for multi-agent applications.

``Agent(prefix="SUPERVISOR")`` resolves its credentials from
``SUPERVISOR_API_KEY_ID`` / ``SUPERVISOR_SECRET`` instead of the default
``MUDRAID_API_KEY_ID`` / ``MUDRAID_SECRET``, so several agents can live in one
process without their credentials overwriting each other.

Naming rule under test (recorded here because it differs from the ticket's
guess): the prefix REPLACES the ``MUDRAID`` segment of the default names, so
the suffixes stay exactly what the unprefixed variables use —
``_API_KEY_ID``, ``_SECRET``, ``_BASE_URL``. The ticket's ``.env`` showed
``SUPERVISOR_KEY_ID`` (no ``API``); that shape is intentionally NOT read.

The isolation fixture mirrors tests/unit/test_env_loader.py: clear every
variable a test could inherit, reset the dotenv-loaded flag, and chdir to a
tmp dir so the repo's real .env is never picked up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from mudraid import Agent, MudraIDConfigError
from mudraid._env import DEFAULT_BASE_URL, load_config

_ALL_VARS = (
    "MUDRAID_API_KEY_ID",
    "MUDRAID_SECRET",
    "MUDRAID_BASE_URL",
    "SUPERVISOR_API_KEY_ID",
    "SUPERVISOR_SECRET",
    "SUPERVISOR_BASE_URL",
    "WEBSITE_API_API_KEY_ID",
    "WEBSITE_API_SECRET",
)


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    for key in _ALL_VARS:
        monkeypatch.delenv(key, raising=False)

    import mudraid._env as env_module

    monkeypatch.setattr(env_module, "_dotenv_loaded", False)
    monkeypatch.chdir(tmp_path)
    yield tmp_path


# ---- resolution -----------------------------------------------------------


def test_prefix_resolves_prefixed_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")

    config = load_config(prefix="SUPERVISOR")
    assert config.api_key_id == "muid_kid_supervisor"
    assert config.secret == "muid_sk_supervisor"


def test_two_prefixes_resolve_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    """The multi-agent scenario from the ticket: two agents, one process,
    no credential overwrites."""
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")
    monkeypatch.setenv("WEBSITE_API_API_KEY_ID", "muid_kid_website")
    monkeypatch.setenv("WEBSITE_API_SECRET", "muid_sk_website")

    supervisor = load_config(prefix="SUPERVISOR")
    website = load_config(prefix="WEBSITE_API")
    assert supervisor.api_key_id == "muid_kid_supervisor"
    assert website.api_key_id == "muid_kid_website"
    assert supervisor.secret != website.secret


def test_prefixed_credentials_loaded_from_dotenv_file(isolated_env: Path) -> None:
    (isolated_env / ".env").write_text(
        "SUPERVISOR_API_KEY_ID=muid_kid_dotenv_sup\nSUPERVISOR_SECRET=muid_sk_dotenv_sup\n"
    )

    config = load_config(prefix="SUPERVISOR")
    assert config.api_key_id == "muid_kid_dotenv_sup"
    assert config.secret == "muid_sk_dotenv_sup"


def test_control_no_prefix_still_reads_mudraid_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """CONTROL (pin) — the unprefixed path is unchanged by this feature."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_default")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_default")

    config = load_config()
    assert config.api_key_id == "muid_kid_default"
    assert config.secret == "muid_sk_default"


# ---- precedence -----------------------------------------------------------


def test_explicit_kwargs_override_prefixed_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_env")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_env")

    config = load_config(
        api_key_id="muid_kid_explicit", secret="muid_sk_explicit", prefix="SUPERVISOR"
    )
    assert config.api_key_id == "muid_kid_explicit"
    assert config.secret == "muid_sk_explicit"


def test_prefix_never_falls_back_to_unprefixed_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Falling back to MUDRAID_* would silently hand one agent another
    agent's identity — the exact bug class the prefix exists to prevent.
    A missing prefixed pair must error, not borrow."""
    monkeypatch.setenv("MUDRAID_API_KEY_ID", "muid_kid_global")
    monkeypatch.setenv("MUDRAID_SECRET", "muid_sk_global")

    with pytest.raises(MudraIDConfigError):
        load_config(prefix="SUPERVISOR")


# ---- error names the prefixed variables -----------------------------------


def test_error_lists_the_prefixed_variable_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """A config error that names the WRONG variables is the DX defect this
    ticket is really about: the developer must be told SUPERVISOR_*, not
    MUDRAID_*."""
    with pytest.raises(MudraIDConfigError) as exc:
        load_config(prefix="SUPERVISOR")
    msg = str(exc.value)
    assert "SUPERVISOR_API_KEY_ID" in msg
    assert "SUPERVISOR_SECRET" in msg
    assert "MUDRAID_API_KEY_ID" not in msg
    assert "MUDRAID_SECRET" not in msg


def test_error_lists_only_the_missing_prefixed_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_present")

    with pytest.raises(MudraIDConfigError) as exc:
        load_config(prefix="SUPERVISOR")
    msg = str(exc.value)
    assert "SUPERVISOR_SECRET" in msg
    assert "SUPERVISOR_API_KEY_ID" not in msg


# ---- base URL: shared global default, per-prefix override ------------------


def test_prefixed_base_url_overrides_global(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "x")
    monkeypatch.setenv("SUPERVISOR_SECRET", "y")
    monkeypatch.setenv("MUDRAID_BASE_URL", "https://api.staging.mudraid.ai")
    monkeypatch.setenv("SUPERVISOR_BASE_URL", "http://localhost:8001")

    config = load_config(prefix="SUPERVISOR")
    assert config.base_url == "http://localhost:8001"


def test_prefix_falls_back_to_global_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """BASE_URL is deployment topology, not identity — unlike credentials it
    IS shared, so the global MUDRAID_BASE_URL applies to prefixed agents."""
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "x")
    monkeypatch.setenv("SUPERVISOR_SECRET", "y")
    monkeypatch.setenv("MUDRAID_BASE_URL", "https://api.staging.mudraid.ai")

    config = load_config(prefix="SUPERVISOR")
    assert config.base_url == "https://api.staging.mudraid.ai"


def test_prefix_falls_back_to_default_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "x")
    monkeypatch.setenv("SUPERVISOR_SECRET", "y")

    config = load_config(prefix="SUPERVISOR")
    assert config.base_url == DEFAULT_BASE_URL


# ---- prefix validation / normalization ------------------------------------


def test_prefix_trailing_underscore_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    """`prefix="SUPERVISOR_"` is an obvious spelling of the same intent —
    normalize it instead of silently looking for SUPERVISOR__API_KEY_ID."""
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")

    config = load_config(prefix="SUPERVISOR_")
    assert config.api_key_id == "muid_kid_supervisor"


def test_prefix_lowercase_is_normalized_to_upper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")

    config = load_config(prefix="supervisor")
    assert config.api_key_id == "muid_kid_supervisor"


@pytest.mark.parametrize(
    "bad_prefix",
    [
        "",  # nothing to name a variable with
        "   ",  # whitespace-only
        "_",  # underscores only
        "BAD-PREFIX",  # '-' is not legal in a POSIX env var name
        "9SUPERVISOR",  # leading digit
        "_SUPERVISOR",  # leading underscore — reserved-looking, refuse not guess
        "SUPER VISOR",  # embedded whitespace
    ],
)
def test_invalid_prefix_is_refused_with_config_error(bad_prefix: str) -> None:
    with pytest.raises(MudraIDConfigError) as exc:
        load_config(prefix=bad_prefix)
    assert "prefix" in str(exc.value).lower()


# ---- Agent constructor wiring ---------------------------------------------


def test_agent_accepts_prefix_kwarg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")

    agent = Agent(prefix="SUPERVISOR")
    assert agent.api_key_id == "muid_kid_supervisor"


def test_agent_legacy_accepts_prefix_kwarg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_API_KEY_ID", "muid_kid_supervisor")
    monkeypatch.setenv("SUPERVISOR_SECRET", "muid_sk_supervisor")

    agent = Agent.legacy(prefix="SUPERVISOR")
    assert agent.api_key_id == "muid_kid_supervisor"


def test_agent_with_prefix_and_missing_vars_names_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(MudraIDConfigError) as exc:
        Agent(prefix="WEBSITE_API")
    msg = str(exc.value)
    assert "WEBSITE_API_API_KEY_ID" in msg
    assert "WEBSITE_API_SECRET" in msg
