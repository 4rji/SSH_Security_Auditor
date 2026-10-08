import pytest

import ssh_auditor.plugins  # noqa: F401  (fuerza el registro de plugins)
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.models import ScanRequest, Status


@pytest.mark.asyncio
async def test_run_scan_negotiation(ssh_server):
    host, port = ssh_server
    cache = TTLCache(ttl_s=60)
    events = []
    req = ScanRequest(
        target_host=host, port=port, profile="generico",
        tests=["connectivity", "negotiation"], policy="base",
    )
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4,
                        cache=cache, on_event=lambda e: events.append(e))
    assert sr.status == "done"
    ids = {r.test_id for r in sr.results}
    assert ids == {"connectivity", "negotiation"}
    assert all(r.status != Status.ERROR for r in sr.results)
    assert cache.get(sr.scan_id) is not None
    assert any(e["type"] == "finished" for e in events)


@pytest.mark.asyncio
async def test_run_scan_unknown_test_is_error(ssh_server):
    host, port = ssh_server
    req = ScanRequest(target_host=host, port=port, tests=["no_existe"], policy="base")
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4, cache=TTLCache(60))
    assert sr.results[0].status == Status.ERROR
