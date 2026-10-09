import asyncio

import pytest

from ssh_auditor.models import AuthMethod, Credentials, Evidence, Status
from ssh_auditor.plugins import concurrency as conc
from ssh_auditor.plugins.base import Context


def _ctx(monkeypatch, latencies, *, limit=4, iterations=50, p95_factor=3,
         error_rate_pct=10):
    calls = {"n": 0}

    async def fake_cycle(ctx):
        i = calls["n"]
        calls["n"] += 1
        outcome = latencies[i] if i < len(latencies) else latencies[-1]
        if isinstance(outcome, Exception):
            raise outcome
        await asyncio.sleep(0)
        return outcome  # ms

    monkeypatch.setattr(conc, "_one_login_cycle", fake_cycle)
    ctx = Context(host="h", port=22,
                  policy={"performance": {"concurrency_success_floor_pct": 95}},
                  params={"load": {"iterations": iterations,
                                   "error_rate_pct": error_rate_pct,
                                   "p95_factor": p95_factor}},
                  emit=lambda _m: None,
                  credentials=Credentials(method=AuthMethod.PASSWORD, username="u",
                                          password="p"),
                  connection_limit=limit)
    return ctx, calls


@pytest.mark.asyncio
async def test_stops_when_error_rate_exceeded(monkeypatch):
    # Baseline (i=0) succeeds; every burst cycle raises -> error rate 100% > 10%.
    ctx, calls = _ctx(monkeypatch, [100, RuntimeError("x")], iterations=50)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["stopped_early"] is True
    assert "error rate" in ev.data["stop_reason"]
    assert calls["n"] < 50  # did not run all 50 bursts


@pytest.mark.asyncio
async def test_p95_only_trips_after_warmup(monkeypatch):
    # Baseline 100ms; first burst sample is huge but must not trip before 10 cycles.
    latencies = [100, 10000] + [100] * 60
    ctx, _ = _ctx(monkeypatch, latencies, iterations=15, p95_factor=3)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["completed"] >= 10  # warmup protected the early slow sample


@pytest.mark.asyncio
async def test_clean_run_reports_latencies(monkeypatch):
    ctx, _ = _ctx(monkeypatch, [100] * 60, iterations=20)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["succeeded"] == 20
    assert ev.data["stopped_early"] is False
    assert ev.data["latency_ms"]["p95"] >= ev.data["latency_ms"]["median"]


def test_evaluate_fail_on_blocked():
    ev = Evidence(data={"applicable": True, "succeeded": 3, "completed": 5,
                        "failed": 2, "stopped_early": True,
                        "stop_reason": "blocked: lockout",
                        "latency_ms": {"min": 1, "median": 2, "p95": 3, "max": 4},
                        "auth_method": "password", "base_login_ms": 100})
    findings = conc.ConcurrencyBoundedPlugin().evaluate(ev, {"performance": {}})
    assert any(f.status == Status.FAIL for f in findings)
