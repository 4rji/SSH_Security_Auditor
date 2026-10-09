import pytest

from ssh_auditor.plugins.authentication import CommandResult
from ssh_auditor.plugins.privileged import SkipReason, SshdTarget, resolve_sshd


def _run_table(table):
    async def run(command, timeout_s=10.0):
        for needle, result in table:
            if needle in command:
                return result
        return CommandResult(stdout="", stderr="", exit_status=127)
    return run


@pytest.mark.asyncio
async def test_resolve_sshd_root_happy_path():
    run = _run_table([
        ("uname -s", CommandResult("Linux", "", 0)),
        ("command -v sshd", CommandResult("/usr/sbin/sshd\n", "", 0)),
        ("stat", CommandResult("0\t755", "", 0)),
        ("-V", CommandResult("", "OpenSSH_9.6p1", 0)),
        ("id -u", CommandResult("0", "", 0)),
    ])
    target = await resolve_sshd(run, profile_id="generic")
    assert isinstance(target, SshdTarget)
    assert target.path == "/usr/sbin/sshd"
    assert target.prefix == []
    assert target.runner == "root"


@pytest.mark.asyncio
async def test_resolve_sshd_non_linux_is_skip():
    run = _run_table([("uname -s", CommandResult("Darwin", "", 0))])
    result = await resolve_sshd(run, profile_id="generic")
    assert isinstance(result, SkipReason)
    assert "Linux" in result.reason
