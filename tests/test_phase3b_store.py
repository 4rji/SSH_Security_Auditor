import pytest

from ssh_auditor.store import Policy, Profile, StoreError, parse


def test_profile_ignores_legacy_detection_commands():
    # Uploaded profiles from before the detection test was removed must keep loading.
    text = "id: linux-box\ndetection:\n  model: cat /etc/device-model\n  firmware: uname -r\n"
    profile = parse("profiles", text)
    assert profile.id == "linux-box"
    assert "detection" not in profile.model_dump()


@pytest.mark.parametrize("command", ["", "id\nreboot", "x\x00y", "x" * 513])
def test_profile_rejects_unsafe_or_unbounded_safe_command(command):
    with pytest.raises(ValueError):
        Profile.model_validate({"id": "bad", "safe_command": command})


def test_policy_accepts_typed_sshd_expectations_and_contexts():
    policy = Policy.model_validate({
        "id": "hardening",
        "sshd": {
            "expected": {
                "passwordauthentication": "no",
                "allowusers": ["audit", "root@192.0.2.*"],
                "maxauthtries": 3,
            },
            "contexts": [{
                "name": "root-from-auditor", "user": "root",
                "host": "auditor.example.test", "addr": "192.0.2.10",
                "expected": {"permitrootlogin": "no"},
            }],
        },
    })
    context = policy.sshd.contexts[0]
    assert context.addr == "192.0.2.10"
    assert context.expected.permitrootlogin == "no"


@pytest.mark.parametrize("body, field", [
    ({"name": "root", "user": "root", "addr": "192.0.2.1"}, "host"),
    ({"name": "root", "user": "root", "host": "source", "addr": "not-an-ip"}, "addr"),
    ({"name": "root", "user": "bad,user", "host": "source", "addr": "192.0.2.1"},
     "user"),
])
def test_policy_rejects_unsafe_or_incomplete_sshd_context(body, field):
    with pytest.raises(ValueError) as exc:
        Policy.model_validate({"id": "bad", "sshd": {"contexts": [body]}})
    assert field in str(exc.value)


def test_policy_rejects_duplicate_context_names():
    context = {"name": "same", "user": "root", "host": "source", "addr": "192.0.2.1"}
    with pytest.raises(ValueError) as exc:
        Policy.model_validate({"id": "bad", "sshd": {"contexts": [context, context]}})
    assert "unique" in str(exc.value)


def test_yaml_parser_rejects_unknown_sshd_directive():
    text = "id: x\nsshd:\n  expected:\n    totallymadeup: yes\n"
    with pytest.raises(StoreError) as exc:
        parse("policies", text)
    assert "totallymadeup" in exc.value.detail
