"""M4.4 — PlatformResolver: bootstrap, host lookup, filtering, refresh.

All tests hit a single mocked endpoint
(``POST /api/v1/auth/agents/me/platforms``) and never touch the
network. Edge cases around URL parsing, case sensitivity, port
handling, and the M0.6b enrichment fields each get their own case so
a future change to ``_build_map`` can't quietly weaken any of them.
"""

from __future__ import annotations

import threading
from typing import Iterator

import pytest
import responses

from mudraid._env import SdkConfig
from mudraid._http import MudraIDHttpClient
from mudraid._platform_resolver import PlatformResolver
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDNetworkError,
    MudraIDPlatformNotRegisteredError,
)

BASE_URL = "https://api.mudraid.test"
BOOTSTRAP_URL = f"{BASE_URL}/api/v1/auth/agents/me/platforms"


def _resolver() -> PlatformResolver:
    config = SdkConfig(
        api_key_id="muid_kid_test",
        secret="muid_sk_test",
        base_url=BASE_URL,
    )
    return PlatformResolver(MudraIDHttpClient(config))


def _entry(
    platform_id: str,
    hostname: str | None,
    *,
    status: str = "active",
    verification_status: str | None = "verified",
    granted_scopes: list[str] | None = None,
    name: str | None = "Test Platform",
) -> dict:
    return {
        "platform_id": platform_id,
        "granted_scopes": granted_scopes or ["read:items"],
        "status": status,
        "name": name,
        "hostname": hostname,
        "verification_status": verification_status,
    }


@pytest.fixture
def rsps() -> Iterator[responses.RequestsMock]:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        yield r


# ---- bootstrap timing ----------------------------------------------------


def test_first_resolve_triggers_bootstrap_http_call(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "agent-1",
            "platforms": [_entry("plt-stripe", "api.stripe.com")],
        },
        status=200,
    )

    pid = _resolver().resolve("https://api.stripe.com/v1/charges")

    assert pid == "plt-stripe"
    assert len(rsps.calls) == 1


def test_second_resolve_uses_cached_map_no_http(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    r = _resolver()
    r.resolve("https://api.foo.com/x")
    r.resolve("https://api.foo.com/y")

    assert len(rsps.calls) == 1, "second resolve must not hit the network"


def test_bootstrap_request_payload_carries_credentials(
    rsps: responses.RequestsMock,
) -> None:
    import json as _json

    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": []},
        status=200,
    )

    try:
        _resolver().resolve("https://api.foo.com/x")
    except MudraIDPlatformNotRegisteredError:
        pass  # Expected — empty platforms list. We only care about the request body.

    body = _json.loads(rsps.calls[0].request.body)
    assert body == {"api_key_id": "muid_kid_test", "secret": "muid_sk_test"}


# ---- host extraction + lookup --------------------------------------------


def test_resolve_is_case_insensitive_on_host(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "a",
            "platforms": [_entry("plt-1", "API.Skyscanner.COM")],
        },
        status=200,
    )

    pid = _resolver().resolve("https://api.skyscanner.com/flights")
    assert pid == "plt-1"


def test_resolve_strips_port_when_matching(rsps: responses.RequestsMock) -> None:
    """Hostnames in MudraID are stored without ports. A URL like
    ``https://api.foo.com:8443/x`` must still resolve."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    pid = _resolver().resolve("https://api.foo.com:8443/health")
    assert pid == "plt-1"


def test_resolve_handles_url_with_path_query_and_fragment(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    pid = _resolver().resolve("https://api.foo.com/v1/items?limit=10#section")
    assert pid == "plt-1"


def test_unknown_host_raises_platform_not_registered(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    with pytest.raises(MudraIDPlatformNotRegisteredError, match="api.bar.com"):
        _resolver().resolve("https://api.bar.com/x")


def test_subdomain_mismatch_does_not_route(rsps: responses.RequestsMock) -> None:
    """Routing is exact-host match for v1, not subdomain wildcard. This
    test locks that in so a future change to add globbing has to opt in
    deliberately."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    with pytest.raises(MudraIDPlatformNotRegisteredError):
        _resolver().resolve("https://api2.foo.com/x")


def test_url_without_host_raises_platform_not_registered(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": []},
        status=200,
    )

    with pytest.raises(MudraIDPlatformNotRegisteredError, match="no host"):
        _resolver().resolve("/relative/path")


# ---- filtering ------------------------------------------------------------


def test_revoked_permissions_are_dropped_from_map(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "a",
            "platforms": [
                _entry("plt-active", "api.active.com"),
                _entry("plt-revoked", "api.revoked.com", status="revoked"),
            ],
        },
        status=200,
    )

    resolver = _resolver()
    assert resolver.resolve("https://api.active.com/x") == "plt-active"
    with pytest.raises(MudraIDPlatformNotRegisteredError):
        resolver.resolve("https://api.revoked.com/x")


def test_entries_with_null_hostname_are_skipped(rsps: responses.RequestsMock) -> None:
    """Per M0.6b, the bootstrap enrichment is best-effort and hostname
    can be ``null`` when platform-integration-service was unavailable.
    Such entries must not appear in the map — without a hostname there
    is nothing to route on."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "a",
            "platforms": [
                _entry("plt-no-host", None),
                _entry("plt-good", "api.good.com"),
            ],
        },
        status=200,
    )

    resolver = _resolver()
    assert resolver.resolve("https://api.good.com/x") == "plt-good"


def test_unverified_platforms_are_skipped(rsps: responses.RequestsMock) -> None:
    """Routing to a non-verified hostname risks delivering a valid JWT
    to an attacker-controlled host that looks like the real one. Only
    ``verification_status == "verified"`` is acceptable."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "a",
            "platforms": [
                _entry("plt-pending", "api.pending.com", verification_status="pending"),
                _entry(
                    "plt-rejected", "api.rejected.com", verification_status="rejected"
                ),
                _entry("plt-expired", "api.expired.com", verification_status="expired"),
                _entry("plt-null", "api.null.com", verification_status=None),
                _entry("plt-verified", "api.verified.com"),
            ],
        },
        status=200,
    )

    resolver = _resolver()
    assert resolver.resolve("https://api.verified.com/x") == "plt-verified"
    for bad_host in (
        "api.pending.com",
        "api.rejected.com",
        "api.expired.com",
        "api.null.com",
    ):
        with pytest.raises(MudraIDPlatformNotRegisteredError):
            resolver.resolve(f"https://{bad_host}/x")


def test_malformed_entries_are_skipped(rsps: responses.RequestsMock) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={
            "agent_id": "a",
            "platforms": [
                {
                    "hostname": "no-platform-id.com",
                    "status": "active",
                    "verification_status": "verified",
                },
                {
                    "platform_id": "plt-no-host",
                    "status": "active",
                    "verification_status": "verified",
                },
                _entry("plt-good", "api.good.com"),
            ],
        },
        status=200,
    )

    assert _resolver().resolve("https://api.good.com/x") == "plt-good"


def test_empty_platforms_list_means_every_resolve_raises(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": []},
        status=200,
    )

    with pytest.raises(MudraIDPlatformNotRegisteredError):
        _resolver().resolve("https://api.foo.com/x")


# ---- refresh --------------------------------------------------------------


def test_refresh_re_bootstraps_on_next_resolve(
    rsps: responses.RequestsMock,
) -> None:
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-old", "api.old.com")]},
        status=200,
    )
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-new", "api.new.com")]},
        status=200,
    )

    resolver = _resolver()
    assert resolver.resolve("https://api.old.com/x") == "plt-old"

    resolver.refresh()

    # Old host no longer registered, new host is.
    with pytest.raises(MudraIDPlatformNotRegisteredError):
        resolver.resolve("https://api.old.com/x")
    assert resolver.resolve("https://api.new.com/x") == "plt-new"

    # Exactly two bootstrap calls — refresh re-triggered exactly once.
    assert len(rsps.calls) == 2


# ---- error propagation ---------------------------------------------------


def test_bootstrap_network_error_propagates(rsps: responses.RequestsMock) -> None:
    import requests as _requests

    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        body=_requests.exceptions.ConnectionError("boom"),
    )

    with pytest.raises(MudraIDNetworkError):
        _resolver().resolve("https://api.foo.com/x")


def test_bootstrap_401_propagates_as_auth_error(rsps: responses.RequestsMock) -> None:
    """The shared HTTP client maps 401 → MudraIDAuthError; the resolver
    must NOT swallow it. A bad api_key_id at bootstrap is a config
    problem and the developer needs to see the same exception they'd
    see from /auth/token."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"detail": "invalid credentials"},
        status=401,
    )

    with pytest.raises(MudraIDAuthError):
        _resolver().resolve("https://api.foo.com/x")


def test_failed_bootstrap_does_not_cache_a_partial_map(
    rsps: responses.RequestsMock,
) -> None:
    """If bootstrap raises, the resolver must remain ``_map is None`` so
    the next resolve retries instead of permanently failing."""
    import requests as _requests

    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        body=_requests.exceptions.ConnectionError("transient"),
    )
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    resolver = _resolver()
    with pytest.raises(MudraIDNetworkError):
        resolver.resolve("https://api.foo.com/x")
    # Second attempt now succeeds — locks in that bootstrap failure is recoverable.
    assert resolver.resolve("https://api.foo.com/x") == "plt-1"


# ---- thread safety -------------------------------------------------------


def test_concurrent_first_resolve_makes_only_one_bootstrap_call(
    rsps: responses.RequestsMock,
) -> None:
    """Double-checked-lock contract: 20 threads hitting a cold resolver
    must produce exactly ONE bootstrap HTTP call. Otherwise we'd
    stampede MudraID under load."""
    rsps.add(
        responses.POST,
        BOOTSTRAP_URL,
        json={"agent_id": "a", "platforms": [_entry("plt-1", "api.foo.com")]},
        status=200,
    )

    resolver = _resolver()
    results: list[str] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(20)

    def worker() -> None:
        barrier.wait()
        try:
            results.append(resolver.resolve("https://api.foo.com/x"))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert results == ["plt-1"] * 20
    assert (
        len(rsps.calls) == 1
    ), "double-checked lock must coalesce concurrent bootstraps"
