"""The single entry point the web API and the MCP server share: the allowlist, the
limits and the input checks are the same whichever way a scan arrives."""
from __future__ import annotations

import json
from dataclasses import dataclass

from ssh_auditor.config import Config, target_allowed
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.jobs import JobsFull, ScanJobs
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.export import to_json
from ssh_auditor.models import ScanRequest, ScanResult
from ssh_auditor.plugins.base import REGISTRY
from ssh_auditor.store import Store, StoreError

# Impact levels that need an explicit confirm_impact=true.
CONFIRM_IMPACTS = ("medium", "high")


class ScanRejected(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Admitted:
    req: ScanRequest  # normalised: tests deduped, policy and concurrency filled in
    policy: dict
    limit: int  # connections allowed against the target, summed over every scan


class AuditService:
    def __init__(self, cfg: Config, tool_version: str):
        self.cfg = cfg
        self.tool_version = tool_version
        self.cache = TTLCache(ttl_s=cfg.cache_ttl_s)
        self.stores = {
            "profiles": Store("profiles", cfg.profiles_dir, cfg.custom_dir or None),
            "policies": Store("policies", cfg.policies_dir, cfg.custom_dir or None),
        }
        self.jobs = ScanJobs(max_active=cfg.max_active_scans, keep_s=cfg.cache_ttl_s)

    def load(self, kind: str, item_id: str):
        try:
            return self.stores[kind].load(item_id)
        except StoreError as e:
            raise ScanRejected(e.status, e.detail) from e

    def admit(self, req: ScanRequest) -> Admitted:
        if not target_allowed(self.cfg, req.target_host):
            raise ScanRejected(403, "Target outside the allowlist, or the allowlist is "
                                    f"empty: {req.target_host}")
        tests = list(dict.fromkeys(req.tests))
        if not tests:
            raise ScanRejected(422, "Choose at least one test.")
        unknown = [t for t in tests if t not in REGISTRY]
        if unknown:
            raise ScanRejected(422, f"Unknown test(s): {', '.join(unknown)}. "
                                    f"Valid: {', '.join(sorted(REGISTRY))}.")
        risky = [t for t in tests if REGISTRY[t].meta.impact in CONFIRM_IMPACTS]
        if risky and not req.confirm_impact:
            raise ScanRejected(422, f"Test(s) {', '.join(risky)} have medium or high impact "
                                    "on the device; repeat the request with confirm_impact "
                                    "set to true once the engineer agrees.")
        profile = self.load("profiles", req.profile)
        limit = profile.limits.max_concurrency
        if req.concurrency is not None and req.concurrency > limit:
            raise ScanRejected(422, f"Concurrency {req.concurrency} exceeds the limit of "
                                    f"profile '{profile.id}' ({limit}).")
        policy_id = req.policy or profile.policy
        policy = self.load("policies", policy_id).model_dump()
        req = req.model_copy(update={
            "tests": tests, "policy": policy_id, "concurrency": req.concurrency or limit,
        })
        return Admitted(req=req, policy=policy, limit=limit)

    async def run(self, adm: Admitted, on_event=None) -> ScanResult:
        """Run an admitted scan to the end (the web waits for it or streams it)."""
        return await run_scan(adm.req, policy=adm.policy, tool_version=self.tool_version,
                              limit=adm.limit, cache=self.cache, on_event=on_event)

    def start(self, req: ScanRequest) -> str:
        """Admit the scan and run it in the background; returns its id at once."""
        adm = self.admit(req)

        def run(scan_id: str, on_event):
            return run_scan(adm.req, policy=adm.policy, tool_version=self.tool_version,
                            limit=adm.limit, cache=self.cache, on_event=on_event,
                            scan_id=scan_id)

        try:
            return self.jobs.start(adm.req.tests, run)
        except JobsFull as e:
            raise ScanRejected(429, str(e)) from e

    async def wait(self, scan_id: str, timeout_s: float) -> None:
        await self.jobs.wait(scan_id, timeout_s)

    def status(self, scan_id: str) -> dict:
        job = self.jobs.get(scan_id)
        if job is not None and job.state != "done":
            out = {
                "scan_id": scan_id, "state": job.state,
                "progress": {"done": len(job.completed), "total": len(job.tests),
                             "completed": list(job.completed)},
            }
            if job.error:
                out["error"] = job.error
            return out
        sr = self.result(scan_id)
        return {
            "scan_id": scan_id, "state": "done",
            "summary": {k.value: v for k, v in sr.summary().items()},
            "result": json.loads(to_json(sr)),
        }

    def result(self, scan_id: str) -> ScanResult:
        """A finished scan from the cache: started from MCP or from the web."""
        sr = self.cache.get(scan_id)
        if sr is not None:
            return sr
        job = self.jobs.get(scan_id)
        if job is not None and job.state == "running":
            raise ScanRejected(409, f"Scan {scan_id} is still running.")
        if job is not None and job.state in ("cancelled", "error"):
            raise ScanRejected(409, f"Scan {scan_id} ended as {job.state}; it has no result.")
        raise ScanRejected(404, f"Scan {scan_id} not found or expired.")

    def cancel(self, scan_id: str) -> dict:
        job = self.jobs.cancel(scan_id)
        if job is None:
            raise ScanRejected(404, f"No background scan {scan_id}: unknown, expired, or "
                                    "started from the web (close its tab to cancel it).")
        return {"scan_id": scan_id, "state": job.state}
