"""The production credential floor's refusal is typed, carried, and actionable.

KAN-171: on a surface whose stored environment is production, identity refuses
a native agent credential with 403 ``code: production_machine_client_required``
and two guidance members. Before this the SDK folded every 403 into
``MudraIDRevokedError`` with the generic "check platform grants" sentence — a
remedy that cannot fix this refusal, because the agent IS granted; it is the
KIND of credential that is wrong.

These tests are about the CONTENT of the error and the attributes a caller can
branch on without parsing prose.
"""

from __future__ import annotations

import json

import pytest
import requests

from mudraid import MudraIDProductionMachineClientRequiredError as Exported
from mudraid._env import SdkConfig
from mudraid._http import MudraIDHttpClient
from mudraid.exceptions import (
    MudraIDError,
    MudraIDProductionMachineClientRequiredError,
    MudraIDRevokedError,
)

BASE_URL = "https://api.staging.mudraid.ai"
SECRET = "muid_sk_" + "s" * 32
PATH = "/api/v1/auth/token"

FLOOR_BODY = {
    "detail": (
        "Native agent credentials are not accepted on production surfaces. "
        "Authenticate as a linked machine client."
    ),
    "code": "production_machine_client_required",
    "recommended_authentication_method": "private_key_jwt",
    "compatibility_authentication_available": True,
}


def _client(status: int, *, body: dict | None = None, raw: bytes | None = None):
    config = SdkConfig(api_key_id="muid_kid_" + "a" * 32, secret=SECRET, base_url=BASE_URL)
    client = MudraIDHttpClient(config)
    response = requests.Response()
    response.status_code = status
    response._content = raw if raw is not None else json.dumps(body or {}).encode()
    client._session.post = lambda *a, **k: response  # type: ignore[method-assign]
    return client


def _raise(**kwargs):
    with pytest.raises(MudraIDProductionMachineClientRequiredError) as exc:
        _client(403, **kwargs).post_json(PATH, {"api_key_id": "x", "secret": SECRET})
    return exc.value


class TestTheTypedRefusal:
    def test_the_floor_code_raises_its_own_class(self):
        error = _raise(body=FLOOR_BODY)
        assert isinstance(error, MudraIDProductionMachineClientRequiredError)

    def test_it_subclasses_revoked_error_so_no_existing_caller_breaks(self):
        error = _raise(body=FLOOR_BODY)
        assert isinstance(error, MudraIDRevokedError)
        assert isinstance(error, MudraIDError)

    def test_it_is_exported_from_the_package_root(self):
        assert Exported is MudraIDProductionMachineClientRequiredError

    def test_the_guidance_members_are_attributes_not_prose(self):
        error = _raise(body=FLOOR_BODY)
        assert error.recommended_authentication_method == "private_key_jwt"
        assert error.compatibility_authentication_available is True

    def test_the_message_carries_the_server_sentence_and_the_remedy(self):
        message = str(_raise(body=FLOOR_BODY))
        assert "not accepted on production surfaces" in message
        assert "private_key_jwt" in message
        assert "MachineAgent" in message
        assert "retry" in message.lower()

    def test_absent_guidance_is_none_never_a_guessed_boolean(self):
        error = _raise(body={"detail": "refused", "code": "production_machine_client_required"})
        assert error.recommended_authentication_method is None
        assert error.compatibility_authentication_available is None
        # The remedy is still named, from the SDK's own knowledge of the contract.
        assert "private_key_jwt" in str(error)

    def test_a_non_boolean_availability_is_not_coerced(self):
        body = dict(FLOOR_BODY, compatibility_authentication_available="yes")
        assert _raise(body=body).compatibility_authentication_available is None

    def test_the_secret_never_leaks_through_this_branch(self):
        assert SECRET not in str(_raise(body=FLOOR_BODY))


class TestNothingElseMoved:
    def test_a_403_with_another_code_is_still_the_generic_revoked_error(self):
        with pytest.raises(MudraIDRevokedError) as exc:
            _client(403, body={"detail": "platform access missing", "code": "other"}).post_json(
                PATH, {"api_key_id": "x", "secret": SECRET}
            )
        assert not isinstance(exc.value, MudraIDProductionMachineClientRequiredError)
        assert "platform access missing" in str(exc.value)

    def test_a_403_with_no_body_keeps_the_generic_grants_sentence(self):
        with pytest.raises(MudraIDRevokedError) as exc:
            _client(403, raw=b"").post_json(PATH, {"api_key_id": "x", "secret": SECRET})
        assert not isinstance(exc.value, MudraIDProductionMachineClientRequiredError)
        assert "check platform grants" in str(exc.value)

    def test_the_floor_code_under_the_error_code_spelling_is_also_recognised(self):
        """`_error_code` now reads both spellings; a server that moved the
        floor to the `error_code` envelope would still be typed."""
        body = dict(FLOOR_BODY)
        body["error_code"] = body.pop("code")
        assert _raise(body=body).recommended_authentication_method == "private_key_jwt"
