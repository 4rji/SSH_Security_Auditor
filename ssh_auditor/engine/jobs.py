"""Scans that run in the background, for MCP: start() answers with the id at once and
the caller polls for progress. Everything stays in RAM; a finished scan's result goes to
the same TTL cache the web uses."""
from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

RunFn = Callable[[str, Callable[[dict], None]], Awaitable[object]]


class JobsFull(Exception):
    pass


@dataclass
class Job:
    scan_id: str
    tests: list[str]
    task: asyncio.Task | None = None
    state: str = "running"  # running | done | cancelled | error
    completed: list[dict] = field(default_factory=list)  # [{"test_id", "status"}]
    error: str = ""
    ended_at: float | None = None


class ScanJobs:
    def __init__(self, max_active: int, keep_s: float):
        self.max_active = max_active
        self.keep_s = keep_s  # how long a finished job's state is kept
        self._jobs: dict[str, Job] = {}

    def active(self) -> int:
        return sum(1 for j in self._jobs.values() if j.state == "running")

    def start(self, tests: list[str], run: RunFn) -> str:
        self._prune()
        if self.active() >= self.max_active:
            raise JobsFull(f"{self.max_active} scans are already running; wait for one "
                           "to finish or cancel one.")
        job = Job(scan_id=uuid.uuid4().hex, tests=list(tests))

        def on_event(ev: dict) -> None:
            if ev.get("type") == "test_done":
                job.completed.append({"test_id": ev["test_id"], "status": ev["status"]})

        async def body() -> None:
            try:
                await run(job.scan_id, on_event)
                job.state = "done"
            except asyncio.CancelledError:
                job.state = "cancelled"
                raise
            except Exception as e:  # noqa: BLE001
                job.state = "error"
                job.error = f"{type(e).__name__}: {e}"
            finally:
                job.ended_at = time.monotonic()

        job.task = asyncio.create_task(body())
        self._jobs[job.scan_id] = job
        return job.scan_id

    def get(self, scan_id: str) -> Job | None:
        self._prune()
        return self._jobs.get(scan_id)

    def cancel(self, scan_id: str) -> Job | None:
        job = self.get(scan_id)
        if job is None:
            return None
        if job.state == "running":
            job.task.cancel()
            # Set here too: a task cancelled before it first runs never enters body().
            job.state = "cancelled"
            job.ended_at = time.monotonic()
        return job

    async def wait(self, scan_id: str, timeout_s: float) -> None:
        """Wait up to timeout_s for the scan to end; never cancels it."""
        job = self._jobs.get(scan_id)
        if job is None or job.task is None or job.task.done() or timeout_s <= 0:
            return
        await asyncio.wait({job.task}, timeout=timeout_s)

    def _prune(self) -> None:
        now = time.monotonic()
        for sid in [s for s, j in self._jobs.items()
                    if j.ended_at is not None and now - j.ended_at >= self.keep_s]:
            del self._jobs[sid]
