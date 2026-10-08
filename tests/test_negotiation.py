import pytest

from ssh_auditor.models import Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins.negotiation import NegotiationPlugin


@pytest.mark.asyncio
async def test_negotiation_reads_algorithms(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    assert len(ev.data["kex"]) > 0
    assert len(ev.data["server_host_key"]) > 0
    assert any(fp.startswith("SHA256:") for fp in ev.data["host_key_fingerprints"].values())
    assert "terrapin" in ev.data and "pq_kex" in ev.data


@pytest.mark.asyncio
async def test_negotiation_policy_flags_prohibited(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    policy = {"kex": {"prohibidos": [ev.data["kex"][0]]}}
    findings = p.evaluate(ev, policy)
    assert any(f.status == Status.FAIL for f in findings)
