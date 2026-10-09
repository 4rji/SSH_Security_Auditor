import pytest
from pydantic import ValidationError

from ssh_auditor.models import AuthMethod, Credentials, ScanRequest


def _request(credentials: Credentials) -> ScanRequest:
    return ScanRequest(target_host="127.0.0.1", tests=["connectivity"],
                       credentials=credentials)


@pytest.mark.parametrize(
    ("method", "fields"),
    [
        (AuthMethod.PASSWORD, {"password": "pw-marker"}),
        (AuthMethod.PRIVATE_KEY, {"private_key": "key-marker"}),
        (AuthMethod.CERTIFICATE,
         {"private_key": "key-marker", "certificate": "cert-marker"}),
        (AuthMethod.KEYBOARD_INTERACTIVE,
         {"keyboard_interactive_responses": ["response-marker"]}),
    ],
)
def test_credentials_validate_each_supported_method(method, fields):
    credentials = Credentials(method=method, username="  audit  ", **fields)
    assert credentials.username == "audit"
    assert credentials.method == method


def test_keyboard_interactive_preserves_an_explicit_empty_response():
    credentials = Credentials(
        method="keyboard_interactive", username="audit",
        keyboard_interactive_responses=["", "otp-marker"],
    )
    assert [value.get_secret_value()
            for value in credentials.keyboard_interactive_responses] == ["", "otp-marker"]


def test_none_method_can_carry_a_username_for_negative_checks():
    credentials = Credentials(method="none", username="  audit  ")
    assert credentials.username == "audit"


@pytest.mark.parametrize(
    "payload",
    [
        {"method": "password", "username": "audit"},
        {"method": "private_key", "username": "audit"},
        {"method": "certificate", "username": "audit", "private_key": "key"},
        {"method": "keyboard_interactive", "username": "audit"},
        {"method": "password", "username": "", "password": "pw"},
    ],
)
def test_credentials_require_only_the_selected_method_fields(payload):
    with pytest.raises(ValidationError):
        Credentials.model_validate(payload)


def test_credentials_are_write_only_and_secret_repr_is_masked():
    marker = "do-not-return-this-password"
    credentials = Credentials(method="password", username="audit", password=marker)
    request = _request(credentials)

    assert marker not in repr(credentials)
    assert "credentials" not in request.model_dump()
    assert marker not in request.model_dump_json()
    assert credentials.password.get_secret_value() == marker

    request_schema = ScanRequest.model_json_schema()
    credentials_schema = request_schema["$defs"]["Credentials"]
    assert request_schema["properties"]["credentials"]["writeOnly"] is True
    for field in (
        "password", "private_key", "private_key_passphrase", "certificate",
        "keyboard_interactive_responses",
    ):
        assert credentials_schema["properties"][field]["writeOnly"] is True


def test_validation_errors_hide_secret_inputs():
    marker = "do-not-print-this-input"
    with pytest.raises(ValidationError) as caught:
        Credentials(method="password", username="audit", password=marker * 1000)

    assert marker not in str(caught.value)


def test_credentials_forbid_unknown_fields():
    with pytest.raises(ValidationError):
        Credentials.model_validate({"method": "none", "unexpected": "value"})

    with pytest.raises(ValidationError):
        ScanRequest.model_validate({
            "target_host": "127.0.0.1", "tests": ["connectivity"],
            "credential": {"method": "none"},
        })


def test_request_target_metadata_has_bounded_defaults():
    request = _request(Credentials())
    assert request.target_name == ""
    assert request.model == ""
    assert request.firmware == ""
    assert request.tags == []
    with pytest.raises(ValidationError):
        ScanRequest(target_host="127.0.0.1", tests=["connectivity"],
                    tags=[str(i) for i in range(33)])
