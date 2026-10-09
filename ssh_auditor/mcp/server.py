"""MCP server: the same engine as the web, exposed as tools for Claude. Every check
(allowlist, limits, impact confirmation) lives in AuditService, so Claude can't go past
what the web can't."""
from __future__ import annotations

import math
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import ValidationError

from ssh_auditor.compare import compare
from ssh_auditor.export import from_json
from ssh_auditor.models import ScanRequest, ScanResult
from ssh_auditor.plugins.base import catalog
from ssh_auditor.service import CONFIRM_IMPACTS, AuditService, ScanRejected

MAX_EXPORT_BYTES = 1024 * 1024
# Below the 60 s after which MCP clients commonly give up on a request.
MAX_WAIT_S = 25

INSTRUCTIONS = f"""\
SSH Security Auditor validates the SSH posture of routers and other network devices on \
the internal network. It is a validation tool, not an attack tool: no brute force. The \
server enforces the target allowlist and each device profile's limits on every request.

Recommended flow:
1. list_tests and list_profiles: what can run, and which device profile fits the device.
2. start_scan with the target, the device profile and the tests. It returns a scan_id at once.
3. get_scan with wait_s (up to {MAX_WAIT_S}) until state is "done". Its `result` is the same JSON the \
web exports.
4. compare_scans with two scan_ids, or with a JSON export the engineer gives you, to find \
regressions between firmware versions or models.
Run the tests in this order: negotiation first (no login), then authentication, then \
yescrypt. This server currently offers the network tests (connectivity and negotiation).

Statuses: PASS meets the policy. WARN works but needs review. FAIL breaks a defined \
requirement. INFO is inventory or evidence without a verdict. SKIP was not run (not \
applicable, or a prerequisite was missing). ERROR means the test could not complete. An \
inconclusive result is WARN or SKIP, never a false PASS or FAIL. Findings about the \
declared version and known CVEs come from the banner, which doesn't prove the real \
version, so they are never FAIL.

Rules: tests with medium or high impact need confirm_impact=true; ask the engineer \
first. Never pass a concurrency above the profile's limit (list_profiles shows it); the \
server rejects it. Results stay in the server's memory for a limited time: tell the \
engineer to export what they want to keep (GET /api/v1/scans/<scan_id>/export?format=\
json|html|csv on this server).
"""


def clamp_wait(wait_s: float) -> float:
    """Seconds get_scan may wait: 0 to MAX_WAIT_S (NaN counts as 0)."""
    return 0 if math.isnan(wait_s) else min(max(wait_s, 0), MAX_WAIT_S)


def build_mcp(service: AuditService) -> MCPServer:
    # log_level: the SDK calls logging.basicConfig with it, which would otherwise raise
    # the whole process to INFO and send every SSH connection's lines to journald.
    mcp = MCPServer("ssh-auditor", title="SSH Security Auditor", instructions=INSTRUCTIONS,
                    version=service.tool_version, log_level="WARNING")

    def _check_shape(name: str, scan_id: str, export: str) -> None:
        if bool(scan_id) == bool(export):
            raise ToolError(f"Give side {name} either a scan id or a JSON export (not both).")

    def _side(name: str, scan_id: str, export: str) -> ScanResult:
        if scan_id:
            try:
                return service.result(scan_id)
            except ScanRejected as e:
                raise ToolError(f"Side {name}: {e.detail}") from e
        if len(export.encode("utf-8")) > MAX_EXPORT_BYTES:
            raise ToolError(f"Side {name}: export too large "
                            f"(max {MAX_EXPORT_BYTES // 1024} KB).")
        try:
            return from_json(export)
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Side {name}: invalid JSON export: {e}") from e

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def list_tests() -> dict[str, Any]:
        """List the available tests: id, name, category, impact on the device, whether
        they need a login, and whether start_scan needs confirm_impact for them."""
        return {"tests": [
            {"id": m.id, "name": m.name, "category": m.category, "version": m.version,
             "impact": m.impact, "requires_auth": m.requires_auth, "timeout_s": m.timeout_s,
             "needs_confirm_impact": m.impact in CONFIRM_IMPACTS}
            for m in catalog()
        ]}

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def list_profiles() -> dict[str, Any]:
        """List the device profiles (shell, connection limits, default policy) and the
        policies. Built-in ones and those engineers uploaded."""
        profiles = []
        for p in service.stores["profiles"].list():
            doc = service.load("profiles", p["id"])
            profiles.append({**p, "shell": doc.shell, "limits": doc.limits.model_dump()})
        return {"device_profiles": profiles, "policies": service.stores["policies"].list()}

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False,
                                          open_world_hint=True))
    async def start_scan(target_host: str, tests: list[str], port: int = 22,
                         profile: str = "generic", policy: str = "", run_by: str = "",
                         concurrency: int | None = None,
                         confirm_impact: bool = False) -> dict[str, Any]:
        """Start a scan in the background and return its scan_id at once; follow it
        with get_scan.

        target_host: IP or FQDN inside the server's allowlist. tests: ids from
        list_tests. profile: device profile id from list_profiles. policy: empty means
        the profile's policy. run_by: the engineer's name, shown in the export.
        concurrency: optional, never above the profile's limit. confirm_impact: true
        only after the engineer agreed to run medium or high impact tests.
        """
        try:
            req = ScanRequest(target_host=target_host, port=port, profile=profile,
                              tests=tests, policy=policy, run_by=run_by,
                              concurrency=concurrency, confirm_impact=confirm_impact)
        except ValidationError as e:
            raise ToolError(f"Invalid input: {e}") from e
        try:
            scan_id = service.start(req)
        except ScanRejected as e:
            raise ToolError(e.detail) from e
        return {"scan_id": scan_id, "state": "running",
                "next": "Call get_scan with this scan_id and wait_s to follow it."}

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def get_scan(scan_id: str, wait_s: float = 0) -> dict[str, Any]:
        """Progress or result of a scan. wait_s (0-25) waits up to that long for it to
        finish before answering. When state is "done", `result` is the full JSON export
        (the same one the web downloads) and `summary` counts results per status."""
        try:
            await service.wait(scan_id, clamp_wait(wait_s))
            return service.status(scan_id)
        except ScanRejected as e:
            raise ToolError(e.detail) from e

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=True))
    async def cancel_scan(scan_id: str) -> dict[str, Any]:
        """Cancel a scan started with start_scan. Its open connections close and it
        leaves no result."""
        try:
            return service.cancel(scan_id)
        except ScanRejected as e:
            raise ToolError(e.detail) from e

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def compare_scans(a_id: str = "", b_id: str = "", a_export: str = "",
                            b_export: str = "") -> dict[str, Any]:
        """Compare two scans. A is the reference ("before"), B the new run ("after").
        Give each side either a scan id (a_id / b_id) or the full text of a JSON export
        (a_export / b_export). Returns per-test changes (Improved, Regressed, Unchanged,
        New, Removed), evidence differences (algorithms added or removed, host key
        change) and warnings when tool, policy or plugin versions differ."""
        # Both sides' shape first, so a missing side is reported before a failed lookup.
        _check_shape("A", a_id, a_export)
        _check_shape("B", b_id, b_export)
        return compare(_side("A", a_id, a_export), _side("B", b_id, b_export))

    return mcp
