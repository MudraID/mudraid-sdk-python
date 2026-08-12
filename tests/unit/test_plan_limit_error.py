"""What the SDK says when the ACCOUNT'S PLAN is what refused, not the network.

THE JOURNEY STEP BEHIND THIS FILE. A registered customer whose first call now
succeeds keeps using the product. Metering's downgrade/trial-expiry path
then enqueues a freeze command, identity-service writes
``agents.billing_state = 'frozen'``, and ``IssueAgentTokenUseCase`` refuses the
next mint with ``BillingFrozenError`` — mapped by
``services/identity-service/app/api/routes/auth.py`` to **HTTP 402** carrying
this sentence:

    This agent is frozen under your current plan. Upgrade your plan in
    Billing to unfreeze and use it again.

``MudraIDHttpClient.post_json`` had branches for 401, 403, 404 and 429 and no
branch for 402, so that sentence was discarded and the customer was handed

    MudraIDNetworkError: unexpected status 402 from MudraID for
    /api/v1/auth/token at https://api.staging.mudraid.ai

``MudraIDNetworkError`` is the one class the published pages tell a reader to
*"retry with backoff — it may be transient"*. A plan freeze is the opposite of
transient: no amount of backoff clears it, and the remedy the server named was
thrown away on the way out. This is the same defect #1081 fixed for 404 and 429,
at the last control-plane status that still had no branch — and it is the one
that matters most to a slot whose charter is *"able to use the service without
limitation"*, because this IS the limitation.

These tests are about the CONTENT of the error and about which class carries it.
The status code was already correct; what a reader could do with it was not.
"""

from __future__ import annotations

import json

import pytest
import requests

from mudraid._env import SdkConfig
from mudraid._http import MudraIDHttpClient
from mudraid.exceptions import (
    MudraIDBillingFrozenError,
    MudraIDError,
    MudraIDNetworkError,
    MudraIDRateLimitedError,
    MudraIDRevokedError,
)

BASE_URL = "https://api.staging.mudraid.ai"
SECRET = "muid_sk_" + "s" * 32
TOKEN_PATH = "/api/v1/auth/token"

#: Verbatim from services/identity-service/app/application/use_cases/
#: issue_agent_token.py — the sentence the server actually sends. Duplicated
#: here on purpose rather than imported: this suite's subject is whether the
#: SDK carries the SERVER'S words through, so it must fail if the SDK starts
#: composing its own.
SERVER_DETAIL = (
    "This agent is frozen under your current plan. Upgrade your plan in "
    "Billing to unfreeze and use it again."
)


def _client(
    status: int,
    *,
    headers: dict | None = None,
    body: dict | None = None,
    raw: bytes | None = None,
):
    """An SDK client whose transport returns exactly one canned response.

    ``raw`` bypasses JSON encoding so a test can serve what a gateway actually
    sends when identity-service is not the thing answering — an HTML page, or
    nothing at all.
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


def _raise_402(**kwargs) -> MudraIDBillingFrozenError:
    with pytest.raises(MudraIDBillingFrozenError) as exc:
        _client(402, **kwargs).post_json(TOKEN_PATH, {"api_key_id": "x", "secret": SECRET})
    return exc.value


class TestTheServerSentenceSurvives:
    def test_the_servers_own_remedy_reaches_the_caller(self):
        message = str(_raise_402(body={"detail": SERVER_DETAIL}))
        assert SERVER_DETAIL in message

    def test_the_message_no_longer_reads_as_an_unexplained_status(self):
        message = str(_raise_402(body={"detail": SERVER_DETAIL}))
        assert "unexpected status" not in message

    def test_it_names_the_path_that_was_refused(self):
        message = str(_raise_402(body={"detail": SERVER_DETAIL}))
        assert TOKEN_PATH in message

    def test_message_form_is_also_accepted(self):
        """identity-service uses ``detail``; the shared JSONResponse refusals in
        the same module use ``message``. Both are the server speaking."""
        message = str(_raise_402(body={"message": SERVER_DETAIL}))
        assert SERVER_DETAIL in message


class TestItIsNotMisattributed:
    """The three wrong readings a bare 402 invited, each pinned."""

    def test_it_does_not_send_the_reader_to_the_credentials(self):
        """The credentials were verified BEFORE this refusal — the freeze check
        in IssueAgentTokenUseCase runs after secret verification. Telling the
        reader to rotate a working secret is the #1081 failure mode."""
        message = str(_raise_402(body={"detail": SERVER_DETAIL})).lower()
        for word in ("secret", "credential", "api_key_id", "rotate"):
            assert word not in message

    def test_it_does_not_name_the_base_url(self):
        """A 404 names ``base_url`` because configuration IS the cause there.
        A 402 is about the account's plan; naming the address would send a
        reader to check a setting that is correct. This assertion is what a
        copy-paste of the 404 branch would fail."""
        assert BASE_URL not in str(_raise_402(body={"detail": SERVER_DETAIL}))

    def test_it_does_not_advise_waiting(self):
        """``MudraIDNetworkError``'s published row says *retry with backoff — it
        may be transient*. This one never clears by waiting, so the message must
        not repeat that advice under a different class."""
        message = str(_raise_402(body={"detail": SERVER_DETAIL})).lower()
        for word in ("backoff", "retry after", "try again in", "propagat"):
            assert word not in message


class TestTheHierarchyContract:
    def test_existing_network_error_handlers_keep_catching_it(self):
        """Before this class existed a 402 raised ``MudraIDNetworkError``. It
        subclasses that DELIBERATELY — the same reasoning ``MudraIDRateLimitedError``
        records — so adding the class breaks nobody and only code that wants the
        distinction has to change."""
        assert issubclass(MudraIDBillingFrozenError, MudraIDNetworkError)
        assert issubclass(MudraIDBillingFrozenError, MudraIDError)

    def test_it_is_not_a_rate_limit(self):
        """Both are refusals a plan can cause and they have different remedies:
        one clears by waiting, this one cannot."""
        assert not issubclass(MudraIDBillingFrozenError, MudraIDRateLimitedError)
        assert not issubclass(MudraIDRateLimitedError, MudraIDBillingFrozenError)

    def test_it_is_exported_from_the_package_root(self):
        import mudraid

        assert mudraid.MudraIDBillingFrozenError is MudraIDBillingFrozenError
        assert "MudraIDBillingFrozenError" in mudraid.__all__


class TestTheSilentServer:
    """A 402 that carries no usable explanation must still be classified, and
    must not have one invented for it."""

    def test_a_non_json_body_still_raises_the_right_class(self):
        assert isinstance(
            _raise_402(raw=b"<html>402 Payment Required</html>"),
            MudraIDBillingFrozenError,
        )

    def test_the_fallback_says_it_is_a_plan_state_and_where_to_look(self):
        message = str(_raise_402(raw=b"")).lower()
        assert "plan" in message
        assert "portal" in message

    def test_the_fallback_does_not_assert_a_reason_it_was_not_given(self):
        """``frozen`` is the server's word for ONE of the states that answers
        402. With no body, the SDK does not get to claim which."""
        assert "frozen" not in str(_raise_402(raw=b"")).lower()


class TestNeighbouringStatusesAreUntouched:
    """The new branch must sit beside the others, not in front of them."""

    def test_403_is_still_a_revocation(self):
        with pytest.raises(MudraIDRevokedError):
            _client(403, body={"detail": "platform access missing"}).post_json(
                TOKEN_PATH, {"api_key_id": "x", "secret": SECRET}
            )

    def test_429_is_still_a_rate_limit(self):
        with pytest.raises(MudraIDRateLimitedError):
            _client(429, body={"error_code": "RATE_LIMITED"}).post_json(
                TOKEN_PATH, {"api_key_id": "x", "secret": SECRET}
            )

    def test_500_still_falls_through_to_the_generic_branch(self):
        """The catch-all is still reachable and still says what it always said —
        this change narrows it by exactly one status, not by a range."""
        with pytest.raises(MudraIDNetworkError) as exc:
            _client(500).post_json(TOKEN_PATH, {"api_key_id": "x", "secret": SECRET})
        assert "unexpected status 500" in str(exc.value)
        assert not isinstance(exc.value, MudraIDBillingFrozenError)
