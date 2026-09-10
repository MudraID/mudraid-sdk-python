"""Environment + .env credential loading.

Reads:

  - ``MUDRAID_API_KEY_ID``  (required)
  - ``MUDRAID_SECRET``      (required)
  - ``MUDRAID_BASE_URL``    (optional; falls back to the production default)

With ``prefix="SUPERVISOR"`` (KAN-90, multi-agent applications) the prefix
REPLACES the ``MUDRAID`` segment of the credential names — the suffixes are
unchanged:

  - ``SUPERVISOR_API_KEY_ID``  (required)
  - ``SUPERVISOR_SECRET``      (required)
  - ``SUPERVISOR_BASE_URL``    (optional; falls back to ``MUDRAID_BASE_URL``,
    then the production default — the base URL is deployment topology, not
    identity, so unlike credentials it is legitimately shared)

Prefixed credentials deliberately do NOT fall back to the unprefixed pair: a
prefixed agent silently borrowing ``MUDRAID_*`` would hand it another agent's
identity, which is the exact bug class the prefix exists to prevent.

Convention: integrators store these in a ``.env`` file in their project
root. python-dotenv loads that file into ``os.environ`` on first access;
explicit arguments to :class:`mudraid.Agent` always win.

The dotenv load uses ``override=False`` so values set by CI, container
orchestrators, or the developer's shell take precedence over whatever
``.env`` says — that matches established Python conventions and prevents
a stale local ``.env`` from leaking into production.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

from dotenv import find_dotenv, load_dotenv

from mudraid.exceptions import MudraIDConfigError

_logger = logging.getLogger("mudraid.env")

#: The host this estate actually serves.
#:
#: It was ``api.mudraid.io`` — one letter, and a domain that appears NOWHERE in
#: MudraID-Infra: not in ``env_domain``, not in ``identity_public_url``, not in
#: a certificate or a DNS record. Production is ``mudraid.ai`` and staging is
#: ``staging.mudraid.ai``. Nobody here can confirm who owns the ``.io``, which
#: is the reason this is a correction and not a tidy-up: a default compiled into
#: an installed package points every unconfigured customer at it, and a default
#: cannot be recalled once it ships — it can only be upgraded away from.
#:
#: THIS DEFAULT STILL DOES NOT WORK ON ITS OWN, and saying so is the point.
#: Production is not provisioned yet, so ``api.mudraid.ai`` does not resolve
#: today either; staging is reached at ``api.staging.mudraid.ai``. No single
#: compiled-in host can be right for both, which is why the documentation tells
#: customers to set ``MUDRAID_BASE_URL`` from the value the product prints on
#: their credential screen. What changed is the failure mode: an unconfigured
#: SDK now fails against a domain we intend to serve, rather than reaching for
#: one we may not own.
DEFAULT_BASE_URL = "https://api.mudraid.ai"

_ENV_API_KEY_ID = "MUDRAID_API_KEY_ID"
_ENV_SECRET = "MUDRAID_SECRET"  # nosec B105 - env-var NAME, not the secret value
_ENV_BASE_URL = "MUDRAID_BASE_URL"

# What a normalized prefix must look like: a POSIX-portable env-var name
# fragment — uppercase letter first, then uppercase letters, digits, or single
# underscores. Leading underscores are refused (reserved-looking), embedded
# doubles are refused rather than collapsed (guessing which variable the
# integrator meant is worse than asking them to spell it).
_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")

# Lazy one-time dotenv load. Filesystem walks are cheap but not free; we
# pay the cost the first time any Agent() is constructed and never again.
# A lock guards the flag against torn writes in multi-threaded apps.
_dotenv_lock = threading.Lock()
_dotenv_loaded = False


def _is_loopback(host: str | None) -> bool:
    """Whether ``host`` names this machine, and therefore never leaves it.

    ``localhost`` by name, plus any literal address inside a loopback range
    (``127.0.0.0/8``, ``::1``) — checked with :mod:`ipaddress` rather than by
    string prefix, so ``127.0.0.1`` and ``127.1.2.3`` are both recognised and
    ``127.0.0.1.evil.example`` is not mistaken for either.
    """
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_base_url(raw: str) -> str:
    """Return ``raw`` if it is a usable control-plane base URL, else raise.

    THE SECRET IS IN THE REQUEST BODY, so the transport is not a preference.
    ``POST /api/v1/auth/token`` and the platform bootstrap both send
    ``{"api_key_id", "secret"}`` as JSON — the agent's long-lived credential, in
    the clear, once per mint. Over ``http://`` that is readable by every hop on
    the path and replayable by any of them, and nothing later in the SDK can
    recover from it: the secret is spent the moment it is sent.

    So ``https`` is required, with exactly one carve-out — a loopback host, where
    there is no network hop to observe. That keeps ``http://localhost:8001``
    working for local development and for the SDK's own integration tests, which
    is the only case anyone actually wants ``http`` for, while a cleartext URL
    pointing anywhere else is refused before a single credential is sent rather
    than warned about in a log nobody is reading.

    Raises:
        MudraIDConfigError: unparseable, hostless, a scheme other than
            http/https, or cleartext ``http`` to a non-loopback host.
    """
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise MudraIDConfigError(
            f"MUDRAID_BASE_URL must be an absolute http(s) URL like "
            f"'{DEFAULT_BASE_URL}'; got {raw!r}"
        )
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise MudraIDConfigError(
            f"MUDRAID_BASE_URL is {raw!r}, which is cleartext http to a remote "
            "host. MudraID's token calls carry this agent's secret in the request "
            "body, so http would disclose it to every hop between here and there. "
            "Use https://. (http:// is permitted only for a loopback host, for "
            "local development.)"
        )
    return raw


def _ensure_dotenv_loaded() -> None:
    """Idempotent ``.env`` discovery + load.

    Safe to call from any entry point. Walks up from the current working
    directory looking for ``.env``; a missing file is not an error (env
    may be provided entirely from the OS, e.g. in a container).

    The search is rooted at ``os.getcwd()``, not at the SDK's installed
    file path. python-dotenv's ``find_dotenv()`` defaults to the latter,
    which would point at site-packages and never find an integrator's
    project ``.env``.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return
    with _dotenv_lock:
        if _dotenv_loaded:
            return
        path = find_dotenv(usecwd=True)
        if path:
            # Log the path (safe — it's a file location) but never the
            # contents. python-dotenv handles the load silently; we
            # don't echo what got set.
            _logger.debug("loaded environment from %s", path)
            load_dotenv(dotenv_path=path, override=False)
        else:
            _logger.debug("no .env file found; relying on OS environment only")
        _dotenv_loaded = True


@dataclass(frozen=True)
class SdkConfig:
    """Resolved SDK configuration.

    Frozen so downstream modules treat it as a value object — nothing in
    the SDK should ever mutate credentials after Agent construction.
    """

    api_key_id: str
    secret: str
    base_url: str
    # Whether ``base_url`` is the compiled-in default rather than a value the
    # integrator chose (kwarg, env or .env). A transport failure against the
    # default is a configuration fact and is reported as one (pre-launch scan
    # SSC-17); the same host set deliberately is not second-guessed.
    base_url_defaulted: bool = False


def _normalize_prefix(prefix: str) -> str:
    """Return the canonical form of a credential prefix, or raise.

    Normalized (obvious spellings of the same intent):
      * surrounding whitespace is stripped
      * lowercase is uppercased (``"supervisor"`` → ``"SUPERVISOR"``)
      * trailing underscores are dropped (``"SUPERVISOR_"`` → ``"SUPERVISOR"``,
        so the variable looked up is ``SUPERVISOR_API_KEY_ID`` and never the
        surprise ``SUPERVISOR__API_KEY_ID``)

    Refused (guessing would resolve credentials from a variable the
    integrator never wrote): empty/whitespace-only, leading digit or
    underscore, embedded whitespace, ``-`` or any other character that is not
    legal in a portable env-var name, and embedded double underscores.

    Raises:
        MudraIDConfigError: with the offending value and the accepted shape.
    """
    normalized = prefix.strip().upper().rstrip("_")
    if not _PREFIX_RE.fullmatch(normalized):
        raise MudraIDConfigError(
            f"Invalid credential prefix {prefix!r}. A prefix must be usable as an "
            "environment-variable name fragment: start with a letter and contain "
            "only letters, digits, and single underscores (e.g. 'SUPERVISOR', "
            "'WEBSITE_API'). It replaces the MUDRAID segment of the variable "
            "names: Agent(prefix='SUPERVISOR') reads SUPERVISOR_API_KEY_ID and "
            "SUPERVISOR_SECRET."
        )
    return normalized


def load_config(
    api_key_id: str | None = None,
    secret: str | None = None,
    base_url: str | None = None,
    prefix: str | None = None,
) -> SdkConfig:
    """Resolve SDK configuration with kwarg > env precedence.

    Precedence (highest first):
      1. Explicit keyword arguments
      2. ``os.environ`` (already populated by the OS / container)
      3. Values from a ``.env`` file in the project tree

    ``prefix`` renames the variables consulted at steps 2–3: the prefix
    replaces the ``MUDRAID`` segment, so ``prefix="SUPERVISOR"`` reads
    ``SUPERVISOR_API_KEY_ID`` / ``SUPERVISOR_SECRET`` / ``SUPERVISOR_BASE_URL``.
    Credentials never fall back from the prefixed names to the unprefixed
    ones (a prefixed agent must not silently borrow another identity); the
    base URL does fall back to ``MUDRAID_BASE_URL`` and then the default,
    because it describes the deployment, not the agent.

    Raises:
        MudraIDConfigError: when ``api_key_id`` or ``secret`` cannot be
            resolved after consulting both kwargs and the environment.
            The error message lists the missing variables — the *prefixed*
            names when a prefix is in play — so the developer doesn't have
            to guess. Also raised for a malformed ``prefix``.
    """
    _ensure_dotenv_loaded()

    if prefix is not None:
        canonical = _normalize_prefix(prefix)
        env_api_key_id = f"{canonical}_API_KEY_ID"
        env_secret = f"{canonical}_SECRET"
        env_base_url = f"{canonical}_BASE_URL"
    else:
        env_api_key_id = _ENV_API_KEY_ID
        env_secret = _ENV_SECRET
        env_base_url = _ENV_BASE_URL

    # ``Optional[str] or str`` evaluates to str at runtime but mypy
    # widens it back to Optional[str]; the ``or ""`` tail pins the
    # type so ``.strip()`` is callable. The behaviour is unchanged.
    resolved_id: str = (api_key_id or os.environ.get(env_api_key_id) or "").strip()
    resolved_secret: str = (secret or os.environ.get(env_secret) or "").strip()
    configured_url = (
        base_url
        or os.environ.get(env_base_url, "").strip()
        # The global base URL backstops every prefix — see the docstring.
        or os.environ.get(_ENV_BASE_URL, "").strip()
    )
    resolved_url = configured_url or DEFAULT_BASE_URL

    missing: list[str] = []
    if not resolved_id:
        missing.append(env_api_key_id)
    if not resolved_secret:
        missing.append(env_secret)
    if missing:
        raise MudraIDConfigError(
            "Missing MudraID credentials: "
            + ", ".join(missing)
            + ". Set them in your .env file or pass api_key_id= / secret= to Agent()."
        )

    config = SdkConfig(
        api_key_id=resolved_id,
        secret=resolved_secret,
        base_url=_validate_base_url(resolved_url.rstrip("/")),
        base_url_defaulted=not configured_url,
    )
    # api_key_id is the *public* half of the credential pair — safe to
    # log. The secret is referenced only by presence, never by value.
    _logger.info(
        "SDK credentials resolved: api_key_id=%s base_url=%s",
        config.api_key_id,
        config.base_url,
    )
    return config
