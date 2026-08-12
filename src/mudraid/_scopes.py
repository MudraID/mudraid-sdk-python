"""Requested-scope value object — the empty-scope-never-all invariant.

This safety invariant lives here as *structure*,
not as a runtime check that a future refactor could forget:

    An omitted scope set requests the empty (minimal) set — never a wildcard.

``RequestedScopes`` can only ever hold a concrete, de-duplicated tuple of named
scope strings. There is **no** constructor, factory, flag, or sentinel that
expands "no scopes" into "all scopes" — that API simply does not exist, so no
amount of convenient client behaviour can broaden authority by omission. The
one way to obtain authority through the SDK is to *name* each scope; naming a
wildcard (``*``, ``all``, ``*:*`` …) is refused up front with
:class:`mudraid.MudraIDScopeError` rather than forwarded to the token endpoint.

On the wire an empty set becomes *no* ``scope`` form field at all (RFC 6749
makes ``scope`` optional). The V2 token endpoint treats an absent/empty scope as
a request for nothing — least privilege by construction — and refuses to expand
it to the client's full entitlement. The legacy ``/api/v1/auth/token`` profile,
by contrast, historically expanded an empty ``scopes`` list to the agent's full
permitted set; that behaviour stays reachable only through the explicitly-named
legacy profile and is out of scope for this value object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from mudraid.exceptions import MudraIDScopeError

# Tokens that would request *broad* authority rather than a specific capability.
# Any of these — in any letter case — is refused, so a caller can never smuggle
# "give me everything" past the type system by spelling it as a string. This is
# a denylist of well-known wildcards; it is intentionally conservative and is
# backed up by the structural guarantee that no "request all" API exists at all.
_WILDCARD_SENTINELS = frozenset(
    {"*", "all", "any", "full", "*:*", "*.*", "*/*", "everything"}
)


@dataclass(frozen=True)
class RequestedScopes:
    """An immutable, de-duplicated set of explicitly named scopes.

    Construct via :meth:`of`. The stored tuple preserves first-seen order so the
    emitted ``scope`` string is stable (useful for request logging and cache
    keys). Frozen + slots-free dataclass so it is safely shareable across
    threads as a value object.
    """

    _scopes: tuple[str, ...]

    @classmethod
    def of(cls, scopes: Iterable[str] | None) -> "RequestedScopes":
        """Build from an iterable of scope strings (or ``None`` / empty).

        ``None`` and an empty iterable both yield the empty set — the minimal
        request, never a wildcard. Blank/whitespace-only entries are dropped.
        Duplicate scopes are collapsed, first occurrence wins.

        Raises:
            MudraIDScopeError: if any entry is a wildcard / "all" token, contains
                a ``*`` glob, or is a non-string. The error is raised before any
                network call so a broadening request never leaves the process.
        """
        if scopes is None:
            return cls(())

        seen: set[str] = set()
        ordered: list[str] = []
        for raw in scopes:
            if not isinstance(raw, str):
                raise MudraIDScopeError(
                    "scopes must be strings naming a specific capability; "
                    f"got a {type(raw).__name__}"
                )
            scope = raw.strip()
            if not scope:
                # A blank entry is not a request for anything — drop it rather
                # than emit a stray space into the scope string.
                continue
            if scope.lower() in _WILDCARD_SENTINELS or "*" in scope:
                raise MudraIDScopeError(
                    "a wildcard / 'all' scope may not be requested: omit scopes to "
                    "request the empty (minimal) set, or name each scope explicitly. "
                    "Convenient breadth is exactly what the V2 profile refuses."
                )
            if scope not in seen:
                seen.add(scope)
                ordered.append(scope)
        return cls(tuple(ordered))

    def is_empty(self) -> bool:
        """True when no scopes were requested (the minimal set)."""
        return not self._scopes

    def as_tuple(self) -> tuple[str, ...]:
        """The named scopes, in first-seen order. Empty for the minimal set."""
        return self._scopes

    def as_scope_param(self) -> str | None:
        """RFC 6749 space-delimited ``scope`` string, or ``None`` when empty.

        Returning ``None`` (rather than ``""``) lets the caller *omit* the
        ``scope`` form field entirely for an empty request — the wire encoding
        of "I am asking for nothing," which the V2 endpoint reads as least
        privilege and never as "everything."
        """
        if not self._scopes:
            return None
        return " ".join(self._scopes)
