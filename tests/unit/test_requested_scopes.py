"""Safety invariant: an empty scope NEVER requests all authority.

These tests lock the *structural* guarantee in :class:`mudraid.RequestedScopes`:

  * omitting scopes (``None`` / empty) yields the empty set, which travels as
    *no* ``scope`` field — never a wildcard;
  * there is no API, flag, or sentinel that turns "no scopes" into "all scopes";
  * an explicit wildcard / "all" token is refused before any network call.

If a future refactor reintroduces an all-authority shortcut, one of these fails.
"""

from __future__ import annotations

import pytest

from mudraid import RequestedScopes
from mudraid.exceptions import MudraIDScopeError

# ---- omission is the empty (minimal) set, never all ----------------------


def test_none_yields_empty_set() -> None:
    scopes = RequestedScopes.of(None)
    assert scopes.is_empty()
    assert scopes.as_tuple() == ()


def test_empty_iterable_yields_empty_set() -> None:
    assert RequestedScopes.of([]).is_empty()
    assert RequestedScopes.of(()).is_empty()


def test_empty_set_emits_no_scope_param() -> None:
    """The wire encoding of 'I am asking for nothing' is an *absent* scope
    field — ``as_scope_param`` returns None, so the caller omits it entirely.
    Emitting nothing is read by the V2 endpoint as least privilege; it is the
    one thing that can never be mistaken for a request for everything."""
    assert RequestedScopes.of(None).as_scope_param() is None
    assert RequestedScopes.of([]).as_scope_param() is None


def test_blank_and_whitespace_entries_are_dropped_not_widened() -> None:
    """A blank scope is not a request for anything and must not become a stray
    space (which could read as an empty-but-present scope). It is dropped."""
    scopes = RequestedScopes.of(["", "  ", "\t"])
    assert scopes.is_empty()
    assert scopes.as_scope_param() is None


# ---- there is NO 'request all' API ---------------------------------------


def test_no_all_authority_constructor_exists() -> None:
    """The invariant as introspection: the value object exposes no wildcard /
    all / everything factory. If someone adds one, this test flags it for an
    explicit security review rather than letting it ship silently."""
    public_api = {name for name in dir(RequestedScopes) if not name.startswith("_")}
    forbidden = {"all", "wildcard", "everything", "full", "any", "unrestricted"}
    leaked = public_api & forbidden
    assert not leaked, f"RequestedScopes must expose no all-authority API; found {leaked}"


@pytest.mark.parametrize(
    "wildcard",
    ["*", "all", "ALL", "All", "any", "full", "*:*", "*.*", "*/*", "everything"],
)
def test_wildcard_scope_is_refused(wildcard: str) -> None:
    """An *explicit* wildcard is an error, not a shortcut — refused before any
    network call so a broadening request never leaves the process."""
    with pytest.raises(MudraIDScopeError):
        RequestedScopes.of([wildcard])


@pytest.mark.parametrize("glob", ["read:*", "*:write", "payments.*", "a*b"])
def test_glob_scope_is_refused(glob: str) -> None:
    """Any scope containing a '*' glob is refused — partial wildcards broaden
    authority just as surely as a bare '*'."""
    with pytest.raises(MudraIDScopeError):
        RequestedScopes.of([glob])


def test_wildcard_mixed_with_named_scopes_still_refused() -> None:
    """A wildcard is not laundered by naming real scopes alongside it."""
    with pytest.raises(MudraIDScopeError):
        RequestedScopes.of(["payments:write", "*"])


def test_non_string_scope_is_refused() -> None:
    with pytest.raises(MudraIDScopeError):
        RequestedScopes.of([object()])  # type: ignore[list-item]


# ---- explicit named scopes are preserved, de-duplicated, ordered ---------


def test_named_scopes_are_preserved_in_order() -> None:
    scopes = RequestedScopes.of(["payments:write", "profile:read"])
    assert not scopes.is_empty()
    assert scopes.as_tuple() == ("payments:write", "profile:read")
    assert scopes.as_scope_param() == "payments:write profile:read"


def test_duplicate_scopes_collapse_first_wins() -> None:
    scopes = RequestedScopes.of(["a:b", "c:d", "a:b"])
    assert scopes.as_tuple() == ("a:b", "c:d")
