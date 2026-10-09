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
