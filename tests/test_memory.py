import pytest

from ssh_auditor.models import Evidence, Status
from ssh_auditor.plugins.memory import MemoryYescryptPlugin

PERF = {"hash_cost_mib": 16, "expected_method": "yescrypt",
        "login_latency_limit_ms": 1500, "mem_warn_fraction": 0.75,
        "concurrency_success_floor_pct": 95}


def _ev(**over):
    data = {"applicable": True, "mem_available_mib": 1531,
            "maxstartups": {"start": 10, "rate": 30, "full": 100},
            "configured_method": "yescrypt", "login_ms": 410, "errors": {}}
    data.update(over)
    return Evidence(data=data)


def _by_id(findings):
    return {f.id: f for f in findings}


def test_worst_case_over_available_is_fail():
    # 100 * 16 = 1600 MiB > 1531 available
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.FAIL


def test_comfortable_margin_is_pass():
    # full=40 -> 640 MiB, well under 0.75*1531
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups={"start": 10, "rate": 30, "full": 40}), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.PASS


def test_latency_over_limit_is_warn_or_fail():
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(login_ms=4000), {"performance": PERF}))
    assert f["login-latency"].status in (Status.WARN, Status.FAIL)


def test_wrong_method_is_warn():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(configured_method="sha512"), {"performance": PERF}))
    assert f["hash-method"].status == Status.WARN


def test_missing_maxstartups_does_not_crash_or_error():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups=None, errors={"maxstartups": "sshd -T unavailable"}),
        {"performance": PERF}))
    assert "pre-auth-memory" not in f or f["pre-auth-memory"].status != Status.ERROR


def test_memory_verdict_is_never_silent_when_data_incomplete():
    # avail present but MaxStartups unreadable: still emit a memory finding explaining it.
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups=None, errors={"maxstartups": "sshd -T unavailable: not Linux"}),
        {"performance": PERF}))
    assert "pre-auth-memory" in f
    assert f["pre-auth-memory"].status in (Status.INFO, Status.SKIP)


def test_latency_recommendation_does_not_blame_yescrypt_on_other_methods():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(login_ms=6000, configured_method="sha512"), {"performance": PERF}))
    assert "yescrypt" not in (f["login-latency"].recommendation or "").lower()


@pytest.mark.asyncio
async def test_collect_never_reads_shadow_and_records_missing_maxstartups(monkeypatch):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from ssh_auditor.models import AuthMethod, Credentials
    from ssh_auditor.plugins import memory as mem
    from ssh_auditor.plugins.authentication import CommandResult
    from ssh_auditor.plugins.base import Context

    issued = []

    @asynccontextmanager
    async def fake_conn(_ctx):
        yield object()

    async def fake_run(_connection, command, timeout_s=10.0, max_output_bytes=65536):
        issued.append(command)
        if "uname -s" in command:
            return CommandResult("Linux", "", 0)
        if "command -v sshd" in command:
            return CommandResult("/usr/sbin/sshd\n", "", 0)
        if "stat" in command:
            return CommandResult("0\t755", "", 0)
        if " -V" in command:
            return CommandResult("OpenSSH_9.6", "", 0)
        if "id -u" in command:
            return CommandResult("0", "", 0)
        if "meminfo" in command:
            return CommandResult("MemAvailable:  1568168 kB", "", 0)
        if "login.defs" in command:
            return CommandResult("ENCRYPT_METHOD SHA512", "", 0)
        if " -T" in command:  # sshd -T without a maxstartups line
            return CommandResult("logingracetime 120\npermitrootlogin no\n", "", 0)
        return CommandResult("", "", 127)

    monkeypatch.setattr(mem, "open_authenticated_connection", fake_conn)
    monkeypatch.setattr(mem, "run_command_on_connection", fake_run)
    ctx = Context(host="h", port=22, policy={}, params={}, emit=lambda _m: None,
                  credentials=Credentials(method=AuthMethod.PASSWORD, username="u",
                                          password="p"),
                  profile=SimpleNamespace(id="generic"))
    ev = await mem.MemoryYescryptPlugin().collect(ctx)
    assert not any("shadow" in c for c in issued)  # hard invariant: never read /etc/shadow
    assert ev.data["configured_method"] == "sha512"
    assert ev.data["mem_available_mib"] == 1568168 // 1024
    assert ev.data["errors"].get("maxstartups")  # sshd -T had no MaxStartups line
