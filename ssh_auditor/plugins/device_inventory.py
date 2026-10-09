from __future__ import annotations

import re

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import run_authenticated_command
from ssh_auditor.plugins.base import Context, Meta, register

MAX_DETECTION_OUTPUT = 4096
MAX_INVENTORY_VALUE = 512
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def _one_line(value: str, limit: int = MAX_INVENTORY_VALUE) -> str:
    """Make command output safe and compact enough for findings and exports."""
    value = _ANSI_ESCAPE.sub("", value)
    lines = []
    for line in value.replace("\r", "\n").splitlines():
        line = "".join(c for c in line if c.isprintable()).strip()
        if line:
            lines.append(line)
    return " / ".join(lines)[:limit]


def _error_text(value: object) -> str:
    return _one_line(str(value), 240) or "unknown error"


class DeviceInventoryPlugin:
    meta = Meta(
        id="device_inventory", version="1", category="A",
        name="Device model and firmware", impact="none",
        requires_auth=True, timeout_s=20.0, privilege="normal",
        actions=("Run the profile's read-only model and firmware detection commands",),
    )

    async def collect(self, ctx: Context) -> Evidence:
        profile = ctx.profile
        if profile is None:
            return Evidence(data={
                "profile": "", "model": None, "firmware": None, "errors": {},
                "skip_reason": "The device profile was not provided to the plugin.",
            })
        commands = {
            "model": profile.detection.model,
            "firmware": profile.detection.firmware,
        }
        configured = {key: command for key, command in commands.items() if command}
        if not configured:
            return Evidence(data={
                "profile": profile.id, "model": None, "firmware": None, "errors": {},
                "skip_reason":
                    f"Profile '{profile.id}' has no model or firmware detection command.",
            })
        credentials = ctx.credentials
        method = (credentials.get("method") if isinstance(credentials, dict)
                  else getattr(credentials, "method", AuthMethod.NONE))
        if method in (None, "", "none", AuthMethod.NONE):
            return Evidence(data={
                "profile": profile.id, "model": None, "firmware": None, "errors": {},
                "skip_reason": "Authenticated credentials are required for device detection.",
            })

        data: dict = {
            "profile": profile.id, "model": None, "firmware": None,
            "errors": {}, "commands": {},
        }
        for field, command in configured.items():
            try:
                result = await run_authenticated_command(
                    ctx, command, timeout_s=8.0, max_output_bytes=MAX_DETECTION_OUTPUT,
                )
            except Exception as exc:  # noqa: BLE001 - a failed detector must not hide the other
                # Authentication/parser exceptions can echo input values. Only the class
                # crosses into evidence; command stderr is handled separately below.
                data["errors"][field] = type(exc).__name__
                continue
            data["commands"][field] = {
                "exit_status": result.exit_status,
                "truncated": result.truncated,
            }
            if result.truncated:
                data["errors"][field] = (
                    f"output exceeded {MAX_DETECTION_OUTPUT} bytes and was discarded"
                )
            elif result.exit_status != 0:
                detail = _error_text(result.stderr)
                data["errors"][field] = (
                    f"command exited with status {result.exit_status}: {detail}"
                )
            else:
                value = _one_line(result.stdout)
                if value:
                    data[field] = value
                else:
                    data["errors"][field] = "command returned no value"
        return Evidence(data=data)

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if data.get("skip_reason"):
            return [Finding(
                id="device-inventory-applicability", status=Status.SKIP,
                summary=data["skip_reason"], source="host",
            )]

        findings = []
        for field, label in (("model", "Device model"), ("firmware", "Firmware")):
            if data.get(field):
                findings.append(Finding(
                    id=field, status=Status.INFO,
                    summary=f"{label}: {data[field]}", source="host",
                ))
            elif field in data.get("errors", {}):
                findings.append(Finding(
                    id=field, status=Status.WARN,
                    summary=f"Could not detect {field}: {data['errors'][field]}",
                    recommendation=f"Review the profile's {field} detection command.",
                    source="host",
                ))
        return findings or [Finding(
            id="device-inventory", status=Status.SKIP,
            summary="No model or firmware value was collected.", source="host",
        )]


register(DeviceInventoryPlugin())
