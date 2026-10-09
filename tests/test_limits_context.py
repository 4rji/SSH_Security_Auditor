import asyncio

import pytest

from ssh_auditor.plugins.base import Context, connection_slot


def _ctx(sem):
    return Context(host="h", port=22, policy={}, params={},
                   emit=lambda _m: None, connection_sem=sem, connection_limit=2)


@pytest.mark.asyncio
async def test_connection_slot_never_exceeds_limit():
    sem = asyncio.Semaphore(2)
    live = 0
    peak = 0

    async def one():
        nonlocal live, peak
        async with connection_slot(_ctx(sem)):
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.01)
            live -= 1

    await asyncio.gather(*(one() for _ in range(10)))
    assert peak <= 2


@pytest.mark.asyncio
async def test_connection_slot_is_noop_without_semaphore():
    async with connection_slot(_ctx(None)):
        pass  # must not raise


@pytest.mark.asyncio
async def test_run_scan_uses_requested_concurrency_as_connection_limit():
    # The per-run concurrency knob must actually size the plugin's limit; it falls back
    # to the profile limit when the request leaves it unset.
    from ssh_auditor.engine.cache import TTLCache
    from ssh_auditor.engine.runner import run_scan
    from ssh_auditor.models import Evidence, Finding, ScanRequest, Status
    from ssh_auditor.plugins.base import REGISTRY, Meta, register

    seen = {}

    class _Probe:
        meta = Meta(id="limit_probe", version="1", category="A", name="p",
                    impact="none", requires_auth=False, timeout_s=1.0)

        async def collect(self, ctx):
            seen["limit"] = ctx.connection_limit
            return Evidence(data={})

        def evaluate(self, _ev, _pol):
            return [Finding(id="p", status=Status.INFO, summary="ok")]

    register(_Probe())
    try:
        await run_scan(ScanRequest(target_host="h", tests=["limit_probe"], concurrency=2),
                       policy={}, tool_version="0", limit=4, cache=TTLCache(60))
        assert seen["limit"] == 2
        await run_scan(ScanRequest(target_host="h", tests=["limit_probe"]),
                       policy={}, tool_version="0", limit=4, cache=TTLCache(60))
        assert seen["limit"] == 4  # unset → profile limit
    finally:
        REGISTRY.pop("limit_probe", None)
