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


def test_agent_constructor_accepts_explicit_credentials() -> None:
    """Construction must succeed with explicit kwargs even before
    M4.2 wires the env loader — otherwise downstream tasks can't
    write tests that don't depend on environment variables."""
    from mudraid import Agent

    Agent(api_key_id="muid_kid_test", secret="muid_sk_test")
    # No exception = pass.


# test_http_methods_raise_until_m4_5_implements_them — removed in M4.5
# along with the NotImplementedError stubs it was guarding. Real
# behavioural coverage of the HTTP methods now lives in
# test_agent_http.py.
