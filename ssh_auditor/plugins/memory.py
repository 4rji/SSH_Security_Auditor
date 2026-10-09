"""Pre-auth memory check for yescrypt (catalog category E).

Read-only and non-intrusive: it reads /proc/meminfo and ``sshd -T`` and times one
password login. It never reads /etc/shadow, never generates hashes, and never changes
a password. The worst-case pre-auth memory figure is a calculation (MaxStartups × the
per-hash cost), not a load test.
"""
from __future__ import annotations

import re
import time

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import (
    open_authenticated_connection, run_command_on_connection,
)
from ssh_auditor.plugins.base import Context, Meta, register
from ssh_auditor.plugins.privileged import SkipReason, effective_sshd, resolve_sshd


def _skip(reason: str) -> Evidence:
    return Evidence(data={"applicable": False, "skip_reason": reason})


def _parse_maxstartups(text: str):
    # From `sshd -T`: "maxstartups 10:30:100" (or a single number).
    for line in text.splitlines():
        if line.startswith("maxstartups"):
            parts = line.split(None, 1)
            spec = parts[1].strip() if len(parts) == 2 else ""
            nums = [int(p) for p in spec.split(":") if p.isdigit()]
            if len(nums) == 1:
                return {"start": nums[0], "rate": 0, "full": nums[0]}
            if len(nums) == 3:
                return {"start": nums[0], "rate": nums[1], "full": nums[2]}
    return None


def _grep_one(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.startswith(key):
            return line[len(key):].strip()
    return ""


class MemoryYescryptPlugin:
    meta = Meta(
        id="memory_yescrypt", version="1", category="E",
        name="Pre-auth memory (yescrypt)", impact="low",
        requires_auth=True, timeout_s=60.0, privilege="root-or-sudo",
        actions=("Read /proc/meminfo and sshd -T (read-only)",
                 "Time one password login", "Read the configured hash method"),
    )

    async def collect(self, ctx: Context) -> Evidence:
        profile = ctx.profile
        if profile is None:
            return _skip("The device profile was not provided to the plugin.")
        method = getattr(ctx.credentials, "method", AuthMethod.NONE)
        if method in (None, "", "none", AuthMethod.NONE):
            return _skip("Authenticated credentials are required for the memory check.")

        errors: dict[str, str] = {}
        data: dict = {"applicable": True, "errors": errors,
                      "mem_available_mib": None, "maxstartups": None,
                      "logingracetime_s": None, "persourcepenalties": None,
                      "configured_method": "unknown", "login_ms": None}

        t0 = time.monotonic()
        try:
            async with open_authenticated_connection(ctx) as connection:
                data["login_ms"] = int((time.monotonic() - t0) * 1000)

                async def run(command, timeout_s=10.0):
                    return await run_command_on_connection(
                        connection, command, timeout_s=timeout_s, max_output_bytes=65536)

                meminfo = await run(
                    "grep -E 'MemTotal|MemFree|MemAvailable' /proc/meminfo", 5.0)
                match = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo.stdout)
                if match:
                    data["mem_available_mib"] = int(match.group(1)) // 1024
                else:
                    errors["mem_available"] = "MemAvailable not found in /proc/meminfo"

                method_cmd = await run(
                    "grep -i '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null; "
                    "grep -i yescrypt /etc/pam.d/common-password /etc/pam.d/system-auth "
                    "2>/dev/null", 5.0)
                blob = method_cmd.stdout.lower()
                if "yescrypt" in blob:
                    data["configured_method"] = "yescrypt"
                elif "sha512" in blob:
                    data["configured_method"] = "sha512"

                target = await resolve_sshd(run, profile_id=profile.id)
                if isinstance(target, SkipReason):
                    errors["maxstartups"] = f"sshd -T unavailable: {target.reason}"
                else:
                    eff = await effective_sshd(run, target)
                    if eff.exit_status == 0 and not eff.truncated:
                        data["maxstartups"] = _parse_maxstartups(eff.stdout)
                        grace = _grep_one(eff.stdout, "logingracetime")
                        data["logingracetime_s"] = int(grace) if grace.isdigit() else None
                        data["persourcepenalties"] = (
                            _grep_one(eff.stdout, "persourcepenalties") or None)
                    else:
                        errors["maxstartups"] = "sshd -T failed"
        except Exception as exc:  # noqa: BLE001 - never surface credential-bearing text
            if data["login_ms"] is None:
                return _skip(
                    f"Could not open the authenticated session: {type(exc).__name__}")
            errors["collect"] = type(exc).__name__
        return Evidence(data=data)

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if not data.get("applicable"):
            return [Finding(id="memory-applicability", status=Status.SKIP,
                            summary=data.get("skip_reason", "Not applicable."),
                            source="host")]
        perf = (policy or {}).get("performance", {})
        cost = perf.get("hash_cost_mib", 16)
        findings: list[Finding] = []

        avail = data.get("mem_available_mib")
        ms = data.get("maxstartups")
        if avail is not None and ms is not None:
            worst = ms["full"] * cost
            slots = avail // cost
            warn_fraction = perf.get("mem_warn_fraction", 0.75)
            if worst > avail:
                status, summary = Status.FAIL, (
                    f"Pre-auth worst case {worst} MiB exceeds MemAvailable {avail} MiB "
                    f"(MaxStartups full={ms['full']} × {cost} MiB).")
                rec = ("Lower the third MaxStartups value, add swap, or set "
                       "PerSourcePenalties.")
            elif worst > avail * warn_fraction:
                status, summary, rec = Status.WARN, (
                    f"Pre-auth worst case {worst} MiB leaves little margin over "
                    f"MemAvailable {avail} MiB."), "Consider lowering MaxStartups."
            else:
                status, summary, rec = Status.PASS, (
                    f"Pre-auth worst case {worst} MiB fits within MemAvailable "
                    f"{avail} MiB."), ""
            findings.append(Finding(id="pre-auth-memory", status=status,
                                    summary=summary, recommendation=rec, source="host"))
            findings.append(Finding(
                id="memory-slots", status=Status.INFO,
                summary=f"~{slots} concurrent yescrypt hashes fit in MemAvailable "
                        f"({avail} MiB / {cost} MiB); quarter≈{(avail // 4) // cost}, "
                        f"third≈{(avail // 3) // cost}.", source="host"))
        elif data.get("errors", {}).get("maxstartups"):
            findings.append(Finding(
                id="memory-maxstartups", status=Status.INFO,
                summary=f"Could not read MaxStartups: {data['errors']['maxstartups']}.",
                source="host"))

        login_ms = data.get("login_ms")
        limit = perf.get("login_latency_limit_ms", 1500)
        if login_ms is not None:
            if login_ms > limit:
                st = Status.FAIL if login_ms > limit * 2 else Status.WARN
                findings.append(Finding(
                    id="login-latency", status=st,
                    summary=f"Password login took {login_ms} ms (limit {limit} ms).",
                    recommendation="Review the yescrypt cost (count) for this platform.",
                    source="host"))
            else:
                findings.append(Finding(
                    id="login-latency", status=Status.PASS,
                    summary=f"Password login took {login_ms} ms (within {limit} ms).",
                    source="host"))

        expected = perf.get("expected_method", "yescrypt")
        observed = data.get("configured_method", "unknown")
        if observed == "unknown":
            findings.append(Finding(
                id="hash-method", status=Status.INFO,
                summary="Could not determine the configured password hash method.",
                source="host"))
        elif observed == expected:
            findings.append(Finding(
                id="hash-method", status=Status.PASS,
                summary=f"Configured password hash method is {observed}.", source="host"))
        else:
            findings.append(Finding(
                id="hash-method", status=Status.WARN,
                summary=f"Configured hash method is {observed}, expected {expected}.",
                recommendation=f"Switch password hashing to {expected}.", source="host"))

        return findings or [Finding(id="memory", status=Status.SKIP,
                                    summary="No memory data collected.", source="host")]


register(MemoryYescryptPlugin())
