from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from ssh_auditor.models import Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins.sshd_config import (
    SshdConfigPlugin, parse_file_stats, parse_sshd_output,
)
from ssh_auditor.store import Policy, Profile


@pytest.fixture(autouse=True)
def _authenticated_connection(monkeypatch):
    @asynccontextmanager
    async def opened(_ctx):
        yield object()

    monkeypatch.setattr(
        "ssh_auditor.plugins.sshd_config.open_authenticated_connection", opened,
    )


def _result(stdout="", stderr="", exit_status=0, truncated=False):
    return SimpleNamespace(stdout=stdout, stderr=stderr, exit_status=exit_status,
                           truncated=truncated)


def _policy() -> Policy:
    return Policy.model_validate({
        "id": "test",
        "sshd": {
            "expected": {
                "passwordauthentication": "no", "pubkeyauthentication": "yes",
                "permitrootlogin": "no", "maxauthtries": 3,
            },
            "contexts": [{
                "name": "root-lab", "user": "root", "host": "auditor.example.test",
                "addr": "192.0.2.10",
                "expected": {"passwordauthentication": "no", "permitrootlogin": "no"},
            }],
        },
    })


def _ctx(profile=None, policy=None) -> Context:
    document = policy or _policy()
    return Context(
        host="127.0.0.1", port=22, policy=document.model_dump(), params={},
        emit=lambda _message: None, profile=profile or Profile(id="linux"),
        credentials={"method": "password"},
    )


def test_parse_sshd_output_preserves_repeated_lists_and_canonical_types():
    settings, malformed = parse_sshd_output("""
passwordauthentication no
allowusers audit
allowusers root@192.0.2.*
maxauthtries 3
unknownsetting ignored
maxsessions not-a-number
""")
    assert settings == {
        "passwordauthentication": "no",
        "allowusers": ["audit", "root@192.0.2.*"],
        "maxauthtries": 3,
    }
    assert malformed == ["line 7: invalid integer for maxsessions"]


def test_parse_file_stats_accepts_only_fixed_sensitive_paths():
    files, malformed = parse_file_stats(
        "/etc/ssh/sshd_config\t0\t0\t644\n"
        "/etc/ssh/sshd_config.d/hardening.conf\t0\t0\t640\n"
        "/etc/ssh/ssh_host_ed25519_key\t0\t0\t600\n"
        "/tmp/other\t0\t0\t600\n"
    )
    assert [item["kind"] for item in files] == [
        "sshd-config", "sshd-config", "host-private-key",
    ]
    assert malformed == ["line 4: invalid stat output"]


@pytest.mark.asyncio
async def test_router_profile_is_skip_without_running_a_command(monkeypatch):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr(SshdConfigPlugin, "_run", forbidden)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx(Profile(id="router", shell="router-cli")))
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.SKIP
    assert "requires a Linux shell" in finding.summary


@pytest.mark.asyncio
async def test_non_linux_and_missing_openssh_are_skip_with_reason(monkeypatch):
    responses = [_result("FreeBSD\n")]

    async def run(*_args, **_kwargs):
        return responses.pop(0)

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx())
    assert plugin.evaluate(evidence, {})[0].status == Status.SKIP
    assert "not Linux" in evidence.data["skip_reason"]

    responses.extend([_result("Linux\n"), _result(stderr="not found", exit_status=1)])
    evidence = await plugin.collect(_ctx())
    assert plugin.evaluate(evidence, {})[0].status == Status.SKIP
    assert evidence.data["skip_reason"] == "OpenSSH sshd was not found on the remote Linux system."


@pytest.mark.asyncio
async def test_sshd_t_and_match_context_are_read_and_evaluated(monkeypatch):
    commands = []
    base_output = """passwordauthentication no
pubkeyauthentication yes
permitrootlogin prohibit-password
maxauthtries 3
allowusers audit
allowusers root@192.0.2.*
"""
    context_output = base_output.replace("permitrootlogin prohibit-password", "permitrootlogin no")

    async def run(_self, _connection, command, _timeout_s=10.0, **_kwargs):
        commands.append(command)
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("0\t755\n")
        if command.endswith(" -V"):
            return _result(stderr="OpenSSH_9.9p2\n")
        if command == "id -u":
            return _result("1000\n")
        if command == "sudo -n -- true":
            return _result()
        if "-C user=root" in command:
            return _result(context_output)
        if "find /etc/ssh" in command:
            return _result(
                "/etc/ssh/sshd_config\t0\t0\t644\n"
                "/etc/ssh/sshd_config.d/10-hardening.conf\t0\t0\t640\n"
                "/etc/ssh/ssh_host_ed25519_key\t0\t0\t600\n"
            )
        return _result(base_output)

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    policy = _policy()
    evidence = await plugin.collect(_ctx(policy=policy))

    assert evidence.data["runner"] == "sudo-n"
    assert evidence.data["default"]["allowusers"] == ["audit", "root@192.0.2.*"]
    context = evidence.data["contexts"][0]
    assert context["settings"]["permitrootlogin"] == "no"
    match_command = next(command for command in commands if "-C user=root" in command)
    assert match_command.startswith("sudo -n -- /usr/sbin/sshd -T")
    assert "-C host=auditor.example.test" in match_command
    assert "-C addr=192.0.2.10" in match_command
    assert "sh -c" not in match_command

    findings = {finding.id: finding for finding in plugin.evaluate(evidence, policy.model_dump())}
    assert {finding.source for finding in findings.values()} == {"host"}
    assert findings["default:permitrootlogin"].status == Status.FAIL
    assert findings["context-root-lab:permitrootlogin"].status == Status.PASS
    assert findings["context-root-lab:passwordauthentication"].status == Status.PASS
    assert findings["context-root-lab:pubkeyauthentication"].status == Status.PASS
    assert findings["context-root-lab:maxauthtries"].status == Status.PASS
    assert findings["file:sshd_config"].status == Status.PASS
    assert findings["file:ssh_host_ed25519_key"].status == Status.PASS


@pytest.mark.asyncio
async def test_insecure_sensitive_file_permissions_fail(monkeypatch):
    base_output = "passwordauthentication no\n"

    async def run(_self, _connection, command, _timeout_s=10.0, **_kwargs):
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("0\t755\n")
        if command.endswith(" -V"):
            return _result(stderr="OpenSSH_9.9\n")
        if command == "id -u":
            return _result("0\n")
        if "find /etc/ssh" in command:
            return _result(
                "/etc/ssh/sshd_config\t1000\t1000\t666\n"
                "/etc/ssh/ssh_host_rsa_key\t0\t0\t640\n"
            )
        return _result(base_output)

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    policy = Policy(id="inventory-only")
    evidence = await plugin.collect(_ctx(policy=policy))
    findings = {finding.id: finding for finding in plugin.evaluate(evidence, policy.model_dump())}
    assert findings["file:sshd_config"].status == Status.FAIL
    assert findings["file:ssh_host_rsa_key"].status == Status.FAIL


@pytest.mark.asyncio
async def test_missing_passwordless_sudo_is_skip(monkeypatch):
    async def run(_self, _connection, command, _timeout_s=10.0, **_kwargs):
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("0\t755\n")
        if command.endswith(" -V"):
            return _result(stderr="OpenSSH_9.8\n")
        if command == "id -u":
            return _result("1000\n")
        return _result(stderr="sudo: a password is required", exit_status=1)

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx())
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.SKIP
    assert "requires root or passwordless sudo" in finding.summary


@pytest.mark.asyncio
async def test_untrusted_sshd_binary_is_never_executed_or_elevated(monkeypatch):
    commands = []

    async def run(_self, _connection, command, _timeout_s=10.0, **_kwargs):
        commands.append(command)
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("1000\t777\n")
        raise AssertionError("untrusted sshd must not be executed")

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx())
    finding = plugin.evaluate(evidence, {})[0]

    assert finding.status == Status.SKIP
    assert "root-owned" in finding.summary
    assert len(commands) == 3


@pytest.mark.asyncio
async def test_invalid_sshd_configuration_is_warn_not_false_pass(monkeypatch):
    async def run(_self, _connection, command, _timeout_s=10.0, **_kwargs):
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("0\t755\n")
        if command.endswith(" -V"):
            return _result(stderr="OpenSSH_9.8\n")
        if command == "id -u":
            return _result("0\n")
        return _result(stderr="/etc/ssh/sshd_config line 7: bad option", exit_status=1)

    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx())
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.WARN
    assert "sshd -T failed" in finding.summary


@pytest.mark.asyncio
async def test_many_contexts_share_one_login_and_fit_the_plugin_timeout(monkeypatch):
    contexts = [
        {
            "name": f"account-{index}", "user": f"user{index}",
            "host": "auditor.example.test", "addr": f"192.0.2.{index + 1}",
        }
        for index in range(16)
    ]
    policy = Policy.model_validate({"id": "many", "sshd": {"contexts": contexts}})
    connection = object()
    opened = 0
    seen_connections = []

    @asynccontextmanager
    async def open_once(_ctx):
        nonlocal opened
        opened += 1
        yield connection

    async def run(_self, current, command, _timeout_s=10.0, **_kwargs):
        seen_connections.append(current)
        if command == "uname -s":
            return _result("Linux\n")
        if "command -v sshd" in command:
            return _result("/usr/sbin/sshd\n")
        if command.startswith("PATH=/usr/bin") and "stat -Lc" in command:
            return _result("0\t755\n")
        if command.endswith(" -V"):
            return _result(stderr="OpenSSH_9.9\n")
        if command == "id -u":
            return _result("0\n")
        if "find /etc/ssh" in command:
            return _result(
                "/etc/ssh/sshd_config\t0\t0\t644\n"
                "/etc/ssh/ssh_host_ed25519_key\t0\t0\t600\n"
            )
        return _result("passwordauthentication no\n")

    monkeypatch.setattr(
        "ssh_auditor.plugins.sshd_config.open_authenticated_connection", open_once,
    )
    monkeypatch.setattr(SshdConfigPlugin, "_run", run)
    plugin = SshdConfigPlugin()
    evidence = await plugin.collect(_ctx(policy=policy))

    assert opened == 1
    assert seen_connections and all(current is connection for current in seen_connections)
    assert len(evidence.data["contexts"]) == 16
    # One connect (10 s), fixed commands (50 s) and sixteen 15 s contexts.
    assert plugin.meta.timeout_s >= 10 + 50 + (16 * 15)
