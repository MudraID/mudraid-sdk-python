"""What the SDK says when MudraID refuses, and whether the reader can act on it.

TWO REAL INCIDENTS SIT BEHIND THIS FILE.

1. A staging agent could not bootstrap. The SDK said `unexpected status 404
   from MudraID` and nothing else. The credentials were valid, the server was
   up, and the cause was that the request reached something which was not
   MudraID's control plane for that agent. Diagnosing it took a hand-written
   probe script comparing three endpoints. The SDK knew the base_url the whole
   time — it logs it at DEBUG — and simply never put it in the message.

2. Identity-service meters the credential-accepting endpoints per api_key_id.
   A 429 fell through to the same catch-all and read `unexpected status 429`,
   which invites exactly the wrong conclusion: that the credentials failed.
   They were never examined.

These tests are about the CONTENT of the error, because content is the whole
defect. The status codes were already correct; what a reader could do with them
was not.
"""

from __future__ import annotations

import json

import pytest
import requests

from mudraid._env import SdkConfig
from mudraid._http import MudraIDHttpClient
from mudraid.exceptions import (
    MudraIDAuthError,
    MudraIDNetworkError,
    MudraIDRateLimitedError,
    MudraIDRevokedError,
)

BASE_URL = "https://api.staging.mudraid.ai"
SECRET = "muid_sk_" + "s" * 32
PATH = "/api/v1/auth/agents/me/platforms"


def _client(
    status: int,
    *,
    headers: dict | None = None,
    body: dict | None = None,
    raw: bytes | None = None,
):
    """An SDK client whose transport returns exactly one canned response.

    ``raw`` bypasses JSON encoding so a test can serve what a gateway or load
    balancer actually sends — an HTML error page, or nothing at all.
    """
    config = SdkConfig(
        api_key_id="muid_kid_" + "a" * 32,
        secret=SECRET,
        base_url=BASE_URL,
    )
    client = MudraIDHttpClient(config)

    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {})
    response._content = (
        raw if raw is not None else json.dumps(body if body is not None else {}).encode()
    )
    client._session.post = lambda *a, **k: response  # type: ignore[method-assign]
    return client


def _raise_429(**kwargs) -> str:
    """Drive one 429 through the client and hand back the message."""
    with pytest.raises(MudraIDRateLimitedError) as exc:
        _client(429, **kwargs).post_json(PATH, {"api_key_id": "x", "secret": SECRET})
    return str(exc.value)


# The ASSERTED forms — the ones that must never appear without evidence.
#
# Deliberately not the bare phrase "per-api_key_id budget": the unattributed
# message legitimately LISTS that limiter as one of three possibilities, and
# banning the words would push the code toward hiding a candidate rather than
# toward not asserting one. What is forbidden is the claim, not the noun.
_PER_KEY_CLAIM_MARKERS = (
    "This one is the per-api_key_id budget",
    "spends it for all three",
)
# ...and the hedge that must be present instead.
_UNATTRIBUTED_MARKER = "did not say which one refused"


class TestUnroutableBaseUrlIsDiagnosable:
    def test_it_names_the_base_url_it_actually_called(self):
        """THE MISSING FACT. Without it the reader has no reason to suspect
        configuration at all — the credentials look like the obvious suspect,
        and they are the one thing that is fine."""
        with pytest.raises(MudraIDNetworkError) as exc:
            _client(404).post_json(PATH, {"api_key_id": "x", "secret": SECRET})

        assert BASE_URL in str(exc.value)

    def test_it_points_at_the_setting_rather_than_the_credentials(self):
        with pytest.raises(MudraIDNetworkError) as exc:
            _client(404).post_json(PATH, {"api_key_id": "x", "secret": SECRET})

        message = str(exc.value)
        assert "MUDRAID_BASE_URL" in message
        # And says WHY a 404 implicates configuration here: these paths always
        # exist, so "not found" is about where the request landed.
        assert "exists on every MudraID deployment" in message

    def test_it_stays_a_network_error_so_existing_handling_keeps_working(self):
        """NEGATIVE CONTROL on the blast radius. The message changed; the type
        did not. Code catching MudraIDNetworkError today is unaffected."""
        with pytest.raises(MudraIDNetworkError):
            _client(404).post_json(PATH, {"api_key_id": "x", "secret": SECRET})


class TestRateLimiting:
    def test_a_429_is_its_own_error_carrying_the_delay_the_server_asked_for(self):
        with pytest.raises(MudraIDRateLimitedError) as exc:
            _client(429, headers={"Retry-After": "42"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )

        assert exc.value.retry_after_seconds == 42
        assert "42s" in str(exc.value)

    def test_it_subclasses_network_error_so_no_existing_caller_breaks(self):
        """Before this change a 429 raised MudraIDNetworkError. Anyone who
        wrote handling for that must keep catching it, or this "improvement"
        silently turns a handled condition into an uncaught crash."""
        with pytest.raises(MudraIDNetworkError):
            _client(429, headers={"Retry-After": "1"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )

    def test_an_unattributed_429_does_not_claim_the_key_budget_was_exhausted(self):
        """THE CORRECTION. Raised in review of #1081: the SDK cannot assume every
        429 came from identity-service's per-api_key_id limiter.

        Kong runs a rate-limiting plugin on the WHOLE identity-service block,
        keyed by caller source rather than by key, and answers with its own body
        carrying no error_code. Blaming the key's budget here sends someone to
        throttle one agent over a limit shared with every other caller behind the
        same egress address — a confident wrong answer, which is worse than the
        vague one this branch replaced.
        """
        message = _raise_429(
            headers={"Retry-After": "30"},
            body={"message": "API rate limit exceeded"},  # Kong's own shape
        )

        for claim in _PER_KEY_CLAIM_MARKERS:
            assert claim not in message, f"attributed to the key on no evidence: {claim!r}"
        assert _UNATTRIBUTED_MARKER in message
        # The candidate may still be NAMED — the reader benefits from knowing
        # what the possibilities are. It must be offered, not asserted.
        assert "may be the per-api_key_id budget" in message
        # And still actionable despite the uncertainty: the one safe instruction
        # that holds whichever limiter spoke.
        assert "Slowing down" in message

    def test_a_body_that_is_not_even_json_is_still_handled_and_still_unattributed(self):
        """An edge under load returns an HTML page, or nothing. Attribution must
        degrade to "unknown" rather than raising inside the error path — a
        parse failure while BUILDING an error message would replace a useful
        429 with a confusing traceback."""
        message = _raise_429(raw=b"<html><body>429 Too Many Requests</body></html>")

        for claim in _PER_KEY_CLAIM_MARKERS:
            assert claim not in message
        assert _UNATTRIBUTED_MARKER in message

    def test_the_key_budget_IS_named_when_the_body_positively_identifies_it(self):
        """The other half of the same rule. Withholding a fact the server did
        state would be its own inaccuracy — this is about evidence, not about
        being vague everywhere."""
        message = _raise_429(
            headers={"Retry-After": "12"},
            body={"error_code": "RATE_LIMITED", "message": "rate limit exceeded"},
        )

        assert "per-api_key_id budget" in message
        assert "spends it for all three" in message

    def test_the_account_fair_use_ceiling_is_not_reported_as_a_per_key_budget(self):
        """A THIRD limiter the review did not name, found while checking the
        claim. identity-service raises FairUseExceededError -> 429 for the
        ACCOUNT's plan ceiling or an abuse block. Calling that a per-key budget
        tells someone to slow one agent down when the limit belongs to the whole
        account and waiting may never clear it."""
        message = _raise_429(
            headers={"Retry-After": "60"},
            body={"error_code": "FAIR_USE_EXCEEDED", "message": "plan ceiling reached"},
        )

        assert "per-api_key_id budget" not in message
        assert "ACCOUNT's fair-use ceiling" in message
        assert "may not clear it" in message

    def test_a_missing_retry_after_is_None_not_a_guessed_default(self):
        """An absence must stay an absence. A fabricated 60 would be
        indistinguishable from a delay the server actually asked for, and a
        caller sleeping on an invented number is the same class of error as
        every other invented value in this codebase."""
        with pytest.raises(MudraIDRateLimitedError) as exc:
            _client(429).post_json(PATH, {"api_key_id": "x", "secret": SECRET})

        assert exc.value.retry_after_seconds is None
        assert "no Retry-After" in str(exc.value)

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"message": "API rate limit exceeded"},
            {"error_code": "RATE_LIMITED", "message": "rate limit exceeded"},
            {"error_code": "FAIR_USE_EXCEEDED", "message": "plan ceiling reached"},
        ],
        ids=["empty", "gateway", "per-key", "fair-use"],
    )
    def test_no_429_reads_as_a_credential_failure_whichever_limiter_spoke(self, body):
        """The whole point, and it has to hold on EVERY branch. The credentials
        were never examined by any of these limiters, so a message that even
        hints at them sends the reader to rotate a working secret.

        Parametrised because the correction added branches: a guarantee proven
        on one path is not a guarantee.
        """
        message = _raise_429(headers={"Retry-After": "5"}, body=body).lower()

        assert "invalid" not in message
        assert "credential" not in message
        assert "rate-limited" in message

    def test_every_429_leads_with_the_same_generic_statement_of_fact(self):
        """What is certainly true comes first; attribution is a qualifier after
        it. A reader who stops at the first sentence is never misled, whichever
        limiter answered."""
        for body in ({}, {"error_code": "RATE_LIMITED"}, {"error_code": "FAIR_USE_EXCEEDED"}):
            assert _raise_429(body=body).startswith("MudraID rate-limited this request to")


class TestNothingElseMoved:
    """The other status mappings are load-bearing and must be untouched."""

    def test_401_is_still_an_auth_error(self):
        with pytest.raises(MudraIDAuthError):
            _client(401).post_json(PATH, {"api_key_id": "x", "secret": SECRET})

    def test_403_is_still_a_revoked_error(self):
        with pytest.raises(MudraIDRevokedError):
            _client(403, body={"detail": "platform access missing"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )

    def test_a_2xx_still_returns_the_parsed_body(self):
        result = _client(200, body={"platforms": []}).post_json(
            PATH, {"api_key_id": "x", "secret": SECRET}
        )
        assert result == {"platforms": []}

    def test_an_unmapped_5xx_still_raises_but_now_says_where(self):
        with pytest.raises(MudraIDNetworkError) as exc:
            _client(503).post_json(PATH, {"api_key_id": "x", "secret": SECRET})
        assert "503" in str(exc.value)
        assert BASE_URL in str(exc.value)


class TestA200ThatIsNotJson:
    """A THIRD INCIDENT, and the one the 404 branch could not catch.

    Reported from staging: `GET /api/v1/auth/agents/me/platforms` against the
    DASHBOARD host returned the React app's `index.html` with status 200, and
    `Agent()` died parsing HTML as JSON.

    That host is a single-page app on a CDN, and such hosting rewrites any
    unknown path to its index page — so the wrong-base_url mistake the 404
    branch was written for arrives here wearing a 200 instead. Every status
    guard passes and `json()` is the first thing to object.

    The old message was `MudraID returned a non-JSON response`: it named
    neither the URL it was pointed at nor what came back, which is precisely
    the gap incident 1 closed for 404s.
    """

    HTML = b"<!doctype html><html><head><title>MudraID</title></head><body></body></html>"

    def _raise(self, **kw) -> str:
        with pytest.raises(MudraIDNetworkError) as exc:
            _client(200, **kw).post_json(PATH, {"api_key_id": "x", "secret": SECRET})
        return str(exc.value)

    def test_it_says_where_it_was_pointed(self):
        message = self._raise(raw=self.HTML, headers={"Content-Type": "text/html"})
        assert BASE_URL in message
        assert PATH in message

    def test_it_says_what_actually_came_back(self):
        message = self._raise(raw=self.HTML, headers={"Content-Type": "text/html; charset=utf-8"})
        # The media type alone — never its parameters, and never the body.
        assert "text/html" in message
        assert "charset" not in message

    def test_html_names_the_single_page_app_cause_and_the_setting_to_check(self):
        message = self._raise(raw=self.HTML, headers={"Content-Type": "text/html"})
        assert "MUDRAID_BASE_URL" in message
        assert "front end" in message

    def test_the_body_is_never_echoed(self):
        # Attacker-controllable in exactly the scenario this refusal exists for,
        # on the same reasoning the redirect branch refuses to echo Location.
        message = self._raise(raw=self.HTML, headers={"Content-Type": "text/html"})
        assert "doctype" not in message.lower()
        assert "<html" not in message.lower()

    def test_a_non_html_non_json_body_still_says_where_without_inventing_a_cause(self):
        message = self._raise(raw=b"OK", headers={"Content-Type": "text/plain"})
        assert BASE_URL in message
        assert "text/plain" in message
        # The single-page-app explanation is specific to HTML and must not be
        # asserted about a body that gives no reason to believe it.
        assert "front end" not in message

    def test_a_missing_content_type_is_not_reported_as_a_type(self):
        message = self._raise(raw=b"\x00\x01")
        assert BASE_URL in message
        assert "It answered" not in message

    def test_it_is_still_a_network_error_so_no_existing_caller_breaks(self):
        with pytest.raises(MudraIDNetworkError):
            _client(200, raw=self.HTML, headers={"Content-Type": "text/html"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )

    def test_the_secret_never_leaks_through_this_branch(self):
        message = self._raise(raw=self.HTML, headers={"Content-Type": "text/html"})
        assert SECRET not in message


class TestTheSecretNeverLeaks:
    """The rule every message in this module is written under. New messages are
    new places for it to escape, so every branch is swept."""

    @pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
    def test_no_error_message_echoes_the_secret(self, status):
        with pytest.raises(Exception) as exc:
            _client(status, headers={"Retry-After": "3"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )
        assert SECRET not in str(exc.value)
        assert "muid_sk_" not in str(exc.value)

    @pytest.mark.parametrize(
        "body",
        [
            {"message": "API rate limit exceeded"},
            {"error_code": "RATE_LIMITED"},
            {"error_code": "FAIR_USE_EXCEEDED"},
            # A server that echoed the secret back would still not get to
            # relay it through us.
            {"error_code": "RATE_LIMITED", "message": f"key {SECRET} over budget"},
        ],
        ids=["gateway", "per-key", "fair-use", "hostile-echo"],
    )
    def test_no_429_attribution_branch_leaks_the_secret(self, body):
        """Each attribution branch is a separate message, so each is a separate
        place for the secret to escape. The last case matters most: attribution
        reads the response body, and a body that contained the secret must not
        become an error message that contains it."""
        message = _raise_429(headers={"Retry-After": "3"}, body=body)

        assert SECRET not in message
        assert "muid_sk_" not in message


class TestTheGatewayCanNowBeNamed:
    """Closing the blind spot the earlier correction deliberately left open.

    That change stopped the SDK asserting the per-key budget on no evidence,
    which was right — but it left EVERY gateway refusal in the "unknown" bucket,
    and the gateway is the most likely source of the three for a customer behind
    a shared egress address.

    The gateway can be named positively without touching gateway config, because
    Kong's rate-limiting plugin already stamps `RateLimit-*` / `X-RateLimit-*`
    on what it meters and identity-service stamps none of them. Header names
    verified against the plugin handler at the image's pinned version (3.9.3),
    not recalled.
    """

    GATEWAY_HEADERS = {
        "RateLimit-Limit": "100",
        "RateLimit-Remaining": "0",
        "RateLimit-Reset": "37",
        "Retry-After": "37",
    }

    def test_a_gateway_refusal_is_now_named_instead_of_shrugged_at(self):
        message = _raise_429(
            headers=self.GATEWAY_HEADERS,
            body={"message": "API rate limit exceeded"},  # Kong's own body
        )

        assert "GATEWAY's limit" in message
        assert _UNATTRIBUTED_MARKER not in message
        # And it must NOT send the reader after their own key.
        for claim in _PER_KEY_CLAIM_MARKERS:
            assert claim not in message

    def test_the_legacy_X_prefixed_family_counts_too(self):
        """Kong emits per-period `X-RateLimit-Limit-Minute` style headers
        alongside the modern ones; a deployment configured for only one period
        may show just those."""
        message = _raise_429(
            headers={"X-RateLimit-Limit-Minute": "100", "X-RateLimit-Remaining-Minute": "0"},
            body={"message": "API rate limit exceeded"},
        )

        assert "GATEWAY's limit" in message

    def test_an_identity_refusal_through_the_gateway_is_still_attributed_to_identity(self):
        """THE TRAP, and the reason precedence is explicit in the code.

        Kong stamps its headers on responses it PROXIES, not only on the ones it
        rejects. So a real identity-service 429 arrives carrying BOTH an
        error_code and a full set of X-RateLimit-* headers. An implementation
        that checked headers first would blame the gateway for every
        application-level refusal in the system — a regression dressed as an
        improvement, and one that no gateway-only test would catch.
        """
        message = _raise_429(
            headers={**self.GATEWAY_HEADERS, "X-RateLimit-Remaining-Minute": "42"},
            body={"error_code": "RATE_LIMITED", "message": "rate limit exceeded"},
        )

        assert "per-api_key_id budget" in message
        assert "GATEWAY's limit" not in message

    def test_the_account_ceiling_also_outranks_the_gateway_headers(self):
        """Same precedence, second application code — the upgrade conversation
        must not be mislabelled as someone else's noisy network."""
        message = _raise_429(
            headers=self.GATEWAY_HEADERS,
            body={"error_code": "FAIR_USE_EXCEEDED", "message": "plan ceiling reached"},
        )

        assert "ACCOUNT's fair-use ceiling" in message
        assert "GATEWAY's limit" not in message

    def test_an_unrecognised_application_code_still_outranks_the_gateway_headers(self):
        """THE THIRD-CODE CASE, and the reason the header branch is gated on
        `code is None` rather than on "neither known code matched".

        Those two guards agree on every case in this module except one: a 429
        whose body carries an application `error_code` this SDK has never heard
        of, because a newer identity-service added it. Today only RATE_LIMITED
        and FAIR_USE_EXCEEDED are emitted, so the weaker guard passes the whole
        suite — which is exactly why this test is written against the case that
        does not exist yet. Under the weaker guard the response falls through
        to the headers and is blamed on the GATEWAY: the same misattribution
        the precedence exists to prevent, arriving silently on a service change
        rather than on a code change here.

        The assertion is deliberately NOT "it names the right layer" — the SDK
        cannot name a code it does not know. It is that the SDK declines to
        name the one layer the body has already ruled out.
        """
        message = _raise_429(
            headers=self.GATEWAY_HEADERS,
            body={"error_code": "SOME_FUTURE_LIMIT", "message": "refused"},
        )

        assert "GATEWAY's limit" not in message
        assert _UNATTRIBUTED_MARKER in message

    def test_retry_after_alone_proves_nothing(self):
        """NEGATIVE CONTROL on the discriminator itself. Both layers send
        Retry-After, so treating it as a gateway signal would attribute every
        unlabelled 429 to the gateway — swapping one confident wrong answer for
        another."""
        message = _raise_429(headers={"Retry-After": "30"}, body={})

        assert "GATEWAY's limit" not in message
        assert _UNATTRIBUTED_MARKER in message

    def test_a_bare_429_with_no_signal_at_all_stays_unattributed(self):
        message = _raise_429(body={})

        assert "GATEWAY's limit" not in message
        assert _UNATTRIBUTED_MARKER in message

    def test_the_gateway_message_still_reads_as_rate_limiting_not_credentials(self):
        message = _raise_429(
            headers=self.GATEWAY_HEADERS, body={"message": "API rate limit exceeded"}
        ).lower()

        assert "invalid" not in message
        assert "credential" not in message
        assert "rate-limited" in message

    def test_the_gateway_branch_does_not_leak_the_secret(self):
        message = _raise_429(
            headers=self.GATEWAY_HEADERS,
            body={"message": f"limit hit for {SECRET}"},
        )

        assert SECRET not in message
        assert "muid_sk_" not in message
