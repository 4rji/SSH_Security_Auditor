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
_REDACTION_MARKERS = ("[REDACTED]", "<hidden>", "***", "")


def _redact_text(value: str, secrets: tuple[str, ...]) -> str:
    """Remove credential values from untrusted plugin/remote text."""
    marker = next(
        candidate for candidate in _REDACTION_MARKERS
        if all(secret not in candidate for secret in secrets)
    )
    for secret in sorted(secrets, key=len, reverse=True):
        # Credentials.secret_values() omits empty values, which would otherwise match
        # between every character.
        value = value.replace(secret, marker)
    return value


def _redact_value(value, secrets: tuple[str, ...]):
    """Recursively redact JSON-like evidence and progress events."""
    if isinstance(value, str):
        return _redact_text(value, secrets)
    if isinstance(value, dict):
        # Keys are schema/structure. Rewriting a key such as "model" because a short
        # password happens to equal it can break downstream interpretation.
        return {key: _redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, secrets) for item in value)
    return value


def _redact_result(result: TestResult, secrets: tuple[str, ...]) -> TestResult:
    """Sanitize every free-text field a plugin or remote host can influence."""
    if not secrets:
        return result
    findings = [
        finding.model_copy(update={
            "summary": _redact_text(finding.summary, secrets),
            "recommendation": _redact_text(finding.recommendation, secrets),
        })
        for finding in result.findings
    ]
    return result.model_copy(update={
        "findings": findings,
        "evidence": Evidence(data=_redact_value(result.evidence.data, secrets)),
    })


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
                              summary=f"Unknown test: {test_id}")],
            evidence=Evidence(data={}), duration_ms=0, impact="none",
        )
    t0 = time.monotonic()
    try:
        async with sem:
            ev = await asyncio.wait_for(plugin.collect(ctx), timeout=plugin.meta.timeout_s)
        findings = plugin.evaluate(ev, ctx.policy)
        status = _rollup(findings)
    except Exception as e:  # noqa: BLE001
        # Plugin exceptions may originate in parsers which received private keys,
        # passwords, or interactive answers. Never copy their text to a result/event.
        error_type = type(e).__name__
        ev = Evidence(data={"error": error_type})
        findings = [Finding(
            id=test_id, status=Status.ERROR,
            summary=f"The test failed with {error_type}; see the server diagnostics.",
        )]
        status = Status.ERROR
    return TestResult(
        test_id=test_id, test_version=plugin.meta.version, category=plugin.meta.category,
        status=status, findings=findings, evidence=ev,
        duration_ms=int((time.monotonic() - t0) * 1000), impact=plugin.meta.impact,
    )


async def run_scan(
    req: ScanRequest, policy: dict, tool_version: str, limit: int,
    cache: TTLCache, on_event=None, scan_id: str | None = None, profile=None,
    connect_host: str | None = None,
) -> ScanResult:
    secrets = req.credentials.secret_values()

    def emit(ev: dict) -> None:
        if on_event:
            # Event type, ids and statuses are controlled structure. Only the log
            # message can contain plugin or remote text.
            if ev.get("type") == "log" and isinstance(ev.get("msg"), str):
                ev = {**ev, "msg": _redact_text(ev["msg"], secrets)}
            on_event(ev)

    scan_id = scan_id or uuid.uuid4().hex
    started = datetime.now(timezone.utc)
    emit({"type": "started", "scan_id": scan_id, "tests": list(req.tests)})
    concrete_host = connect_host or req.target_host
    sem = _LIMITS.semaphore(concrete_host, limit)
    results: list[TestResult] = []
    for tid in req.tests:
        ctx = Context(
            host=concrete_host, port=req.port, policy=policy, params=req.params,
            emit=lambda m: emit({"type": "log", "msg": m}),
            credentials=req.credentials, profile=profile,
        )
        tr = _redact_result(await _run_one(tid, ctx, sem), secrets)
        results.append(tr)
        emit({"type": "test_done", "test_id": tid, "status": tr.status.value})

    sr = ScanResult(
        scan_id=scan_id, target_host=req.target_host, port=req.port, profile=req.profile,
        target_name=_redact_text(req.target_name.strip(), secrets),
        model=_redact_text(req.model.strip(), secrets),
        firmware=_redact_text(req.firmware.strip(), secrets),
        tags=[_redact_text(tag, secrets) for tag in req.tags],
        policy_name=req.policy, started_at=started, finished_at=datetime.now(timezone.utc),
        status="done", results=results, tool_version=tool_version,
        run_by=_redact_text(req.run_by.strip(), secrets),
    )
    cache.put(scan_id, sr)
    emit({"type": "finished", "scan_id": scan_id,
          "summary": {k.value: v for k, v in sr.summary().items()}})
    return sr
