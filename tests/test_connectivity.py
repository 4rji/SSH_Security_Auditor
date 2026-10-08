import pytest

from ssh_auditor.models import Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins.connectivity import ConnectivityPlugin


@pytest.mark.asyncio
async def test_connectivity_reaches_server(ssh_server):
    host, port = ssh_server
    p = ConnectivityPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    assert ev.data["tcp_open"] is True
    assert ev.data["banner"].startswith("SSH-2.0")
    findings = p.evaluate(ev, {})
    assert any(f.status == Status.PASS for f in findings)


@pytest.mark.asyncio
async def test_connectivity_refused_port():
    p = ConnectivityPlugin()
    ev = await p.collect(Context(host="127.0.0.1", port=1, policy={}, params={}, emit=lambda m: None))
    assert ev.data["tcp_open"] is False
    findings = p.evaluate(ev, {})
    assert any(f.status in (Status.FAIL, Status.ERROR) for f in findings)
