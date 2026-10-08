from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone

from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.limits import LimitRegistry
from ssh_auditor.models import (
    Evidence, Finding, ScanRequest, ScanResult, Status, TestResult,
)
from ssh_auditor.plugins.base import Context, REGISTRY

_LIMITS = LimitRegistry()


def _rollup(findings: list[Finding]) -> Status:
    order = [Status.ERROR, Status.FAIL, Status.WARN, Status.PASS, Status.INFO, Status.SKIP]
    present = {f.status for f in findings}
    for s in order:
        if s in present:
            return s
    return Status.SKIP


async def _run_one(test_id: str, ctx: Context, sem: asyncio.Semaphore) -> TestResult:
    plugin = REGISTRY.get(test_id)
    if plugin is None:
        return TestResult(
            test_id=test_id, test_version="0", category="?",
            status=Status.ERROR,
            findings=[Finding(id=test_id, status=Status.ERROR,
                              summary=f"Prueba desconocida: {test_id}")],
            evidence=Evidence(data={}), duration_ms=0, impact="none",
        )
    t0 = time.monotonic()
    try:
        async with sem:
            ev = await asyncio.wait_for(plugin.collect(ctx), timeout=plugin.meta.timeout_s)
        findings = plugin.evaluate(ev, ctx.policy)
        status = _rollup(findings)
    except Exception as e:  # noqa: BLE001
        ev = Evidence(data={"error": f"{type(e).__name__}: {e}"})
        findings = [Finding(id=test_id, status=Status.ERROR, summary=str(e) or type(e).__name__)]
        status = Status.ERROR
    return TestResult(
        test_id=test_id, test_version=plugin.meta.version, category=plugin.meta.category,
        status=status, findings=findings, evidence=ev,
        duration_ms=int((time.monotonic() - t0) * 1000), impact=plugin.meta.impact,
    )


async def run_scan(
    req: ScanRequest, policy: dict, tool_version: str, limit: int,
    cache: TTLCache, on_event=None,
) -> ScanResult:
    def emit(ev: dict) -> None:
        if on_event:
            on_event(ev)

    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc)
    emit({"type": "started", "scan_id": scan_id, "tests": list(req.tests)})
    sem = _LIMITS.semaphore(req.target_host, limit)
    results: list[TestResult] = []
    for tid in req.tests:
        ctx = Context(
            host=req.target_host, port=req.port, policy=policy, params=req.params,
            emit=lambda m: emit({"type": "log", "msg": m}),
        )
        tr = await _run_one(tid, ctx, sem)
        results.append(tr)
        emit({"type": "test_done", "test_id": tid, "status": tr.status.value})

    sr = ScanResult(
        scan_id=scan_id, target_host=req.target_host, port=req.port, profile=req.profile,
        policy_name=req.policy, started_at=started, finished_at=datetime.now(timezone.utc),
        status="done", results=results, tool_version=tool_version,
    )
    cache.put(scan_id, sr)
    emit({"type": "finished", "scan_id": scan_id,
          "summary": {k.value: v for k, v in sr.summary().items()}})
    return sr
