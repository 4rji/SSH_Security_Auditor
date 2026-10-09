from types import SimpleNamespace

import pytest

from ssh_auditor.models import Evidence, Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins.device_inventory import DeviceInventoryPlugin
from ssh_auditor.store import Profile


def _ctx(profile: Profile) -> Context:
    return Context(host="127.0.0.1", port=22, policy={}, params={},
                   emit=lambda _message: None, profile=profile,
                   credentials={"method": "password"})


def _result(stdout="", stderr="", exit_status=0, truncated=False):
    return SimpleNamespace(stdout=stdout, stderr=stderr, exit_status=exit_status,
                           truncated=truncated)


@pytest.mark.asyncio
async def test_inventory_runs_profile_commands_and_sanitizes_values(monkeypatch):
    profile = Profile(id="box", detection={
        "model": "read-model", "firmware": "read-firmware",
    })

    async def run(_ctx, command, **_kwargs):
        return (_result("\x1b[31mRouter 9000\x1b[0m\n") if command == "read-model"
                else _result("v1.2\nrelease 7\n"))

    monkeypatch.setattr("ssh_auditor.plugins.device_inventory.run_authenticated_command", run)
    plugin = DeviceInventoryPlugin()
    evidence = await plugin.collect(_ctx(profile))

    assert evidence.data["model"] == "Router 9000"
    assert evidence.data["firmware"] == "v1.2 / release 7"
    findings = plugin.evaluate(evidence, {})
    assert {item.status for item in findings} == {Status.INFO}
    assert {item.source for item in findings} == {"host"}


@pytest.mark.asyncio
async def test_inventory_without_commands_is_skip_and_does_not_connect(monkeypatch):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr(
        "ssh_auditor.plugins.device_inventory.run_authenticated_command", forbidden,
    )
    plugin = DeviceInventoryPlugin()
    evidence = await plugin.collect(_ctx(Profile(id="router", shell="router-cli")))
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.SKIP
    assert "no model or firmware detection command" in finding.summary


@pytest.mark.asyncio
async def test_inventory_never_serializes_local_exception_text(monkeypatch):
    profile = Profile(id="box", detection={"model": "read-model"})

    async def run(*_args, **_kwargs):
        raise ValueError("secret-password")

    monkeypatch.setattr("ssh_auditor.plugins.device_inventory.run_authenticated_command", run)
    evidence = await DeviceInventoryPlugin().collect(_ctx(profile))
    assert evidence.data["errors"]["model"] == "ValueError"
    assert "secret-password" not in Evidence.model_validate(evidence).model_dump_json()


@pytest.mark.asyncio
async def test_inventory_without_credentials_is_skip_not_warn(monkeypatch):
    profile = Profile(id="box", detection={"model": "read-model"})
    ctx = _ctx(profile)
    ctx.credentials = None

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr("ssh_auditor.plugins.device_inventory.run_authenticated_command", forbidden)
    plugin = DeviceInventoryPlugin()
    evidence = await plugin.collect(ctx)
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.SKIP
    assert finding.summary == "Authenticated credentials are required for device detection."


@pytest.mark.asyncio
async def test_inventory_failure_is_warn_and_remote_stderr_is_bounded(monkeypatch):
    profile = Profile(id="box", detection={"firmware": "read-firmware"})

    async def run(*_args, **_kwargs):
        return _result(stderr="permission denied\n" + "x" * 1000, exit_status=1)

    monkeypatch.setattr("ssh_auditor.plugins.device_inventory.run_authenticated_command", run)
    plugin = DeviceInventoryPlugin()
    evidence = await plugin.collect(_ctx(profile))
    finding = plugin.evaluate(evidence, {})[0]
    assert finding.status == Status.WARN
    assert len(evidence.data["errors"]["firmware"]) < 300
