import asyncio

import pytest

from ssh_auditor.engine.jobs import JobsFull, ScanJobs


def _fake(gate: asyncio.Event | None = None, fail: bool = False):
    async def run(scan_id, on_event):
        on_event({"type": "test_done", "test_id": "t1", "status": "PASS"})
        if gate is not None:
            await gate.wait()
        if fail:
            raise RuntimeError("boom")
        return scan_id
    return run


@pytest.mark.asyncio
async def test_job_runs_in_background_and_reports_progress():
    jobs = ScanJobs(max_active=2, keep_s=60)
    gate = asyncio.Event()
    sid = jobs.start(["t1", "t2"], _fake(gate))
    await asyncio.sleep(0)  # let the task reach the gate
    job = jobs.get(sid)
    assert job.state == "running"
    assert job.completed == [{"test_id": "t1", "status": "PASS"}]
    gate.set()
    await jobs.wait(sid, 5)
    assert jobs.get(sid).state == "done"


@pytest.mark.asyncio
async def test_wait_returns_on_timeout_without_stopping_the_scan():
    jobs = ScanJobs(max_active=2, keep_s=60)
    gate = asyncio.Event()
    sid = jobs.start(["t1"], _fake(gate))
    await jobs.wait(sid, 0.05)
    assert jobs.get(sid).state == "running"
    gate.set()
    await jobs.wait(sid, 5)
    assert jobs.get(sid).state == "done"


@pytest.mark.asyncio
async def test_cancel_stops_the_scan():
    jobs = ScanJobs(max_active=2, keep_s=60)
    gate = asyncio.Event()
    sid = jobs.start(["t1"], _fake(gate))
    await asyncio.sleep(0)
    assert jobs.cancel(sid).state == "cancelled"
    await jobs.wait(sid, 1)
    assert jobs.get(sid).task.cancelled() and jobs.get(sid).state == "cancelled"
    # Cancelled before it even started running.
    sid2 = jobs.start(["t1"], _fake(gate))
    jobs.cancel(sid2)
    await jobs.wait(sid2, 1)
    assert jobs.get(sid2).state == "cancelled"
    assert jobs.cancel("unknown") is None


@pytest.mark.asyncio
async def test_failed_run_is_reported_as_error():
    jobs = ScanJobs(max_active=2, keep_s=60)
    sid = jobs.start(["t1"], _fake(fail=True))
    await jobs.wait(sid, 5)
    job = jobs.get(sid)
    assert job.state == "error" and "boom" in job.error


@pytest.mark.asyncio
async def test_active_limit_and_pruning():
    jobs = ScanJobs(max_active=1, keep_s=0)
    gate = asyncio.Event()
    sid = jobs.start(["t1"], _fake(gate))
    with pytest.raises(JobsFull):
        jobs.start(["t1"], _fake())
    gate.set()
    await jobs.wait(sid, 5)
    jobs.start(["t1"], _fake())  # a slot is free again
    assert jobs.get(sid) is None  # keep_s=0: the finished job was pruned
