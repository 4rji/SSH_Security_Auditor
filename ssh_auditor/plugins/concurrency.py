"""Bounded concurrency and stability test (catalog category F).

A login burst capped at the profile's max_concurrency, with automatic stop on error
rate, p95 latency, or a block/lockout signal. It measures posture under controlled
load; it is not a search for the device's breaking point.
"""
from __future__ import annotations

import asyncio
import time

import asyncssh

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import (
    _context_credentials, _safe_command, open_authenticated_connection,
    run_command_on_connection,
)
from ssh_auditor.plugins.base import Context, Meta, register

WARMUP_CYCLES = 10
_BLOCK_SIGNALS = ("too many authentication", "too many sessions", "connection refused",
                  "connection reset", "max startups")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round((pct / 100) * (len(ordered) - 1))))
    return ordered[k]


async def _one_login_cycle(ctx: Context) -> float:
    """Open one authenticated connection, run the harmless command, close it.
    Return the elapsed milliseconds. Raises on failure (caught by the caller)."""
    command = _safe_command(ctx)
    start = time.monotonic()
    async with open_authenticated_connection(ctx) as connection:
        await run_command_on_connection(connection, command, timeout_s=10.0)
    return (time.monotonic() - start) * 1000


def _is_block_signal(exc: Exception) -> bool:
    if isinstance(exc, asyncssh.PermissionDenied):
        return True  # lockout / rejected credential during the burst
    text = str(exc).lower()
    return any(sig in text for sig in _BLOCK_SIGNALS)


class ConcurrencyBoundedPlugin:
    meta = Meta(
        id="concurrency_bounded", version="1", category="F",
        name="Bounded concurrency", impact="medium",
        requires_auth=True, timeout_s=330.0, privilege="normal",
        actions=("Measure one baseline login",
                 "Run bounded concurrent login/command/logout cycles",
                 "Stop automatically on errors, latency, or a block signal"),
    )

    async def collect(self, ctx: Context) -> Evidence:
        credentials = _context_credentials(ctx)
        if credentials.method == AuthMethod.NONE:
            return Evidence(data={
                "applicable": False,
                "skip_reason": "Choose an authentication method for this test."})

        load = (ctx.params or {}).get("load", {})
        iterations = int(load.get("iterations") or 1)
        error_rate_pct = float(load.get("error_rate_pct", 10))
        p95_factor = float(load.get("p95_factor", 3))
        concurrency = max(1, int(ctx.connection_limit))

        # Baseline login (also verifies the credential before the burst).
        try:
            base_ms = await _one_login_cycle(ctx)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, asyncssh.PermissionDenied):
                return Evidence(data={
                    "applicable": True, "base_login_ms": None,
                    "completed": 0, "succeeded": 0, "failed": 0,
                    "stopped_early": True, "stop_reason": "rejected",
                    "auth_method": credentials.method.value, "latency_ms": {}})
            return Evidence(data={
                "applicable": False,
                "skip_reason": f"Baseline login failed: {type(exc).__name__}"})

        latencies: list[float] = []
        completed = succeeded = failed = 0
        stop_reason = ""
        sem = asyncio.Semaphore(concurrency)
        emit = ctx.emit
        stop = asyncio.Event()

        async def one(_i: int):
            nonlocal completed, succeeded, failed, stop_reason
            if stop.is_set():
                return
            async with sem:
                if stop.is_set():
                    return
                try:
                    ms = await _one_login_cycle(ctx)
                    latencies.append(ms)
                    succeeded += 1
                except Exception as exc:  # noqa: BLE001 - classify without leaking text
                    failed += 1
                    if _is_block_signal(exc):
                        stop_reason = "blocked: a block/lockout signal was received"
                        stop.set()
                finally:
                    completed += 1
                # Auto-stop checks after each completed cycle.
                if not stop.is_set():
                    if completed and (failed / completed) * 100 > error_rate_pct:
                        stop_reason = f"error rate exceeded {error_rate_pct:g}%"
                        stop.set()
                    elif completed >= WARMUP_CYCLES and latencies:
                        if _percentile(latencies, 95) > p95_factor * base_ms:
                            stop_reason = (
                                f"p95 latency exceeded {p95_factor:g}× the baseline")
                            stop.set()
                emit(f"cycle {completed}/{iterations} ok={succeeded} fail={failed}")

        await asyncio.gather(*(one(i) for i in range(iterations)))

        latency_ms = {}
        if latencies:
            latency_ms = {
                "min": int(min(latencies)), "median": int(_percentile(latencies, 50)),
                "p95": int(_percentile(latencies, 95)), "max": int(max(latencies)),
            }
        return Evidence(data={
            "applicable": True, "auth_method": credentials.method.value,
            "base_login_ms": int(base_ms),
            "requested": {"concurrency": concurrency, "iterations": iterations,
                          "error_rate_pct": error_rate_pct, "p95_factor": p95_factor},
            "completed": completed, "succeeded": succeeded, "failed": failed,
            "latency_ms": latency_ms,
            "stopped_early": bool(stop_reason), "stop_reason": stop_reason,
        })

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if not data.get("applicable"):
            return [Finding(id="concurrency-applicability", status=Status.SKIP,
                            summary=data.get("skip_reason", "Not applicable."),
                            source="host")]
        perf = (policy or {}).get("performance", {})
        floor = perf.get("concurrency_success_floor_pct", 95)
        completed = data.get("completed", 0)
        succeeded = data.get("succeeded", 0)
        reason = data.get("stop_reason", "")
        success_pct = (succeeded / completed * 100) if completed else 0

        if reason.startswith("blocked") or reason == "rejected":
            status = Status.FAIL
        elif reason.startswith("error rate"):
            status = Status.FAIL
        elif success_pct < floor:
            status = Status.FAIL
        elif reason.startswith("p95"):
            status = Status.WARN
        elif success_pct < 100:
            status = Status.WARN
        else:
            status = Status.PASS

        lat = data.get("latency_ms", {})
        lat_text = (f"min {lat['min']} / median {lat['median']} / p95 {lat['p95']} / "
                    f"max {lat['max']} ms") if lat else "no successful cycles"
        summary = (f"{succeeded}/{completed} successful ({success_pct:.0f}%) over "
                   f"{data.get('auth_method')}; latency {lat_text}.")
        if reason:
            summary += f" Stopped early: {reason}."
        rec = ("Reduce concurrency/iterations or investigate the device limits."
               if status == Status.FAIL else "")
        return [Finding(id="concurrency_bounded", status=status, summary=summary,
                        recommendation=rec, source="host")]


register(ConcurrencyBoundedPlugin())
