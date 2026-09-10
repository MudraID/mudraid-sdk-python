"""M4.1 smoke tests.

These assert only that the package scaffold is importable and the
public names exist. Behavioural tests are added in M4.2+ as each
module gains real logic.
"""

from __future__ import annotations


def test_public_api_is_importable() -> None:
    """A consumer's `from mudraid import Agent` must work from a fresh install."""
    from mudraid import Agent, MudraIDError

    assert Agent is not None
    assert issubclass(MudraIDError, Exception)


def test_version_is_exposed() -> None:
    """Tooling needs `mudraid.__version__` to display in error reports."""
    import mudraid

    assert isinstance(mudraid.__version__, str)
    assert mudraid.__version__.count(".") == 2  # semver-shaped


def test_agent_defaults_to_machine_authority() -> None:
    from mudraid import Agent, MachineAgent

    assert Agent is MachineAgent
    assert not hasattr(Agent, "legacy")
