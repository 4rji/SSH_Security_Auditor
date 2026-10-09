from __future__ import annotations

import re
import shlex

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import (
    open_authenticated_connection, run_command_on_connection,
)
from ssh_auditor.plugins.base import Context, Meta, register

MAX_SSHD_OUTPUT = 512 * 1024

_MULTI_VALUE = {"allowusers", "denyusers", "allowgroups", "denygroups"}
_INTEGER_VALUE = {
    "maxauthtries", "logingracetime", "maxsessions",
    "clientaliveinterval", "clientalivecountmax",
}
_DIRECTIVES = {
    "passwordauthentication", "pubkeyauthentication", "kbdinteractiveauthentication",
    "permitrootlogin", *_MULTI_VALUE, *_INTEGER_VALUE,
    "maxstartups", "persourcepenalties", "tcpkeepalive", "unusedconnectiontimeout",
    "channeltimeout", "usepam",
}
_ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
_HOST_KEY = re.compile(r"^/etc/ssh/ssh_host_[A-Za-z0-9_-]+_key$")


def _safe_text(value: object, limit: int = 300) -> str:
    text = " ".join(str(value).replace("\r", "\n").splitlines())
    text = "".join(c for c in text if c.isprintable())
    return text[:limit].strip() or "unknown error"


def parse_sshd_output(output: str) -> tuple[dict, list[str]]:
    """Parse and filter ``sshd -T`` output.

    OpenSSH prints one ``keyword value`` per line and repeats list directives such as
    AllowUsers. Unknown settings are intentionally left out of exported evidence.
    """
    settings: dict = {}
    malformed: list[str] = []
    for number, raw in enumerate(output.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        key = _ALIASES.get(parts[0].lower(), parts[0].lower())
        if key not in _DIRECTIVES:
            continue
        if len(parts) != 2 or not parts[1].strip():
            malformed.append(f"line {number}: {_safe_text(line, 120)}")
            continue
        value: object = parts[1].strip()
        if key in _INTEGER_VALUE:
            try:
                value = int(value)
            except ValueError:
                malformed.append(f"line {number}: invalid integer for {key}")
                continue
        if key in _MULTI_VALUE:
            settings.setdefault(key, []).extend(str(value).split())
        else:
            settings[key] = value
    return settings, malformed


def parse_file_stats(output: str) -> tuple[list[dict], list[str]]:
    """Parse the fixed tab-separated ``stat`` format used by the collector."""
    files = []
    malformed = []
    for number, raw in enumerate(output.splitlines(), 1):
        parts = raw.split("\t")
        if len(parts) != 4:
            malformed.append(f"line {number}: invalid stat output")
            continue
        path, uid, gid, mode = parts
        allowed = (path == "/etc/ssh/sshd_config"
                   or (path.startswith("/etc/ssh/sshd_config.d/") and path.endswith(".conf"))
                   or bool(_HOST_KEY.fullmatch(path)))
        if (not allowed or not uid.isdigit() or not gid.isdigit()
                or not re.fullmatch(r"[0-7]{3,4}", mode)):
            malformed.append(f"line {number}: invalid stat output")
            continue
        files.append({
            "path": path, "uid": int(uid), "gid": int(gid), "mode": mode[-3:],
            "kind": "host-private-key" if _HOST_KEY.fullmatch(path) else "sshd-config",
        })
    return files, malformed


def _skip(reason: str, **extra) -> Evidence:
    return Evidence(data={"applicable": False, "skip_reason": reason, **extra})


def _command(argv: list[str]) -> str:
    """Build one remote shell command while keeping every variable a literal argv item."""
    return shlex.join(argv)


def _connection_args(context: dict) -> list[str]:
    args = [
        "-C", f"user={context['user']}",
        "-C", f"host={context['host']}",
        "-C", f"addr={context['addr']}",
    ]
    if context.get("invalid_user"):
        args += ["-C", "invalid-user"]
    return args


def _sshd_policy(policy: dict) -> dict:
    value = policy.get("sshd") or {}
    return value if isinstance(value, dict) else {}


class SshdConfigPlugin:
    meta = Meta(
        id="sshd_config", version="1", category="D",
        name="Effective OpenSSH configuration", impact="none",
        # At most 16 policy contexts are allowed. Each can consume 15 seconds, plus
        # the prerequisite/default/file checks and the initial SSH connection.
        requires_auth=True, timeout_s=330.0, privilege="root-or-sudo",
        actions=("Run read-only OpenSSH sshd -T and sshd -T -C checks",),
    )

    async def _run(self, connection, command: str, timeout_s: float = 10.0):
        return await run_command_on_connection(
            connection, command, timeout_s=timeout_s,
            max_output_bytes=MAX_SSHD_OUTPUT,
        )

    async def collect(self, ctx: Context) -> Evidence:
        profile = ctx.profile
        if profile is None:
            return _skip("The device profile was not provided to the plugin.")
        if profile.shell != "linux":
            return _skip(
                f"Profile '{profile.id}' declares shell '{profile.shell}'; effective sshd "
                "configuration requires a Linux shell.", profile=profile.id,
            )
        credentials = ctx.credentials
        method = (credentials.get("method") if isinstance(credentials, dict)
                  else getattr(credentials, "method", AuthMethod.NONE))
        if method in (None, "", "none", AuthMethod.NONE):
            return _skip(
                "Authenticated credentials are required to read effective sshd configuration.",
                profile=profile.id,
            )

        connected = False
        try:
            async with open_authenticated_connection(ctx) as connection:
                connected = True
                return await self._collect_connected(ctx, profile, connection)
        except Exception as exc:  # noqa: BLE001 - prerequisite authentication failed
            if connected:
                raise
            return _skip(
                f"Could not open the authenticated SSH session: {type(exc).__name__}",
                profile=profile.id,
            )

    async def _collect_connected(self, ctx: Context, profile, connection) -> Evidence:
        from ssh_auditor.plugins.privileged import SkipReason, resolve_sshd

        async def run(command, timeout_s=10.0):
            return await self._run(connection, command, timeout_s)

        target = await resolve_sshd(run, profile_id=profile.id)
        if isinstance(target, SkipReason):
            return _skip(target.reason, profile=profile.id, **target.extra)
        path, prefix, runner, version, system = (
            target.path, target.prefix, target.runner, target.version, target.system)

        policy = _sshd_policy(ctx.policy)
        base_argv = [*prefix, path, "-T"]
        base = await self._run(connection, _command(base_argv), 15.0)
        if base.exit_status != 0 or base.truncated:
            detail = (_safe_text(base.stderr)
                      if not base.truncated else f"output exceeded {MAX_SSHD_OUTPUT} bytes")
            return Evidence(data={
                "applicable": True, "profile": profile.id, "system": system,
                "sshd_path": path, "version": version, "runner": runner,
                "default": {}, "contexts": [],
                "collection_error": f"sshd -T failed: {detail}",
            })

        default, malformed = parse_sshd_output(base.stdout)
        contexts = []
        for context in policy.get("contexts", []):
            connection_spec = {
                key: context[key] for key in ("user", "host", "addr", "invalid_user")
                if key in context
            }
            result = await self._run(
                connection,
                _command([*base_argv, *_connection_args(connection_spec)]),
                15.0,
            )
            item = {"name": context["name"], "connection": connection_spec}
            if result.exit_status != 0 or result.truncated:
                item["settings"] = {}
                item["error"] = (
                    f"output exceeded {MAX_SSHD_OUTPUT} bytes" if result.truncated
                    else f"sshd -T -C failed: {_safe_text(result.stderr)}"
                )
            else:
                item["settings"], item["malformed"] = parse_sshd_output(result.stdout)
            contexts.append(item)

        # Fixed paths and a fixed stat format keep this read-only and make its output
        # safe to parse. shlex.join quotes find's parentheses, glob patterns and ';'.
        files_command = _command([
            *prefix, "find", "/etc/ssh", "-maxdepth", "2", "-type", "f", "(",
            "-path", "/etc/ssh/sshd_config", "-o",
            "-path", "/etc/ssh/sshd_config.d/*.conf", "-o",
            "-name", "ssh_host_*_key", ")", "-exec", "stat", "-Lc",
            "%n\t%u\t%g\t%a", "--", "{}", ";",
        ])
        files_result = await self._run(connection, files_command, 10.0)
        files, files_malformed = parse_file_stats(files_result.stdout)
        files_error = ""
        if files_result.truncated:
            files_error = f"file metadata output exceeded {MAX_SSHD_OUTPUT} bytes"
        elif files_result.exit_status != 0:
            files_error = f"file metadata command failed: {_safe_text(files_result.stderr)}"

        return Evidence(data={
            "applicable": True, "profile": profile.id, "system": system,
            "sshd_path": path, "version": version, "runner": runner,
            "default": default, "malformed": malformed, "contexts": contexts,
            "files": files, "files_malformed": files_malformed,
            "files_error": files_error,
        })

    @staticmethod
    def _scope_findings(scope: str, actual: dict, expected: dict) -> list[Finding]:
        findings = []
        for directive, wanted in expected.items():
            if wanted is None:
                continue
            finding_id = f"{scope}:{directive}"
            access_note = ("; effective account access rule, no login attempted"
                           if directive in _MULTI_VALUE else "")
            if directive not in actual:
                findings.append(Finding(
                    id=finding_id, status=Status.WARN,
                    summary=f"{scope}: sshd -T did not report {directive}",
                    recommendation="Check whether this OpenSSH version supports the directive.",
                    source="host",
                ))
            elif actual[directive] == wanted:
                findings.append(Finding(
                    id=finding_id, status=Status.PASS,
                    summary=(f"{scope}: {directive} = {actual[directive]!r} "
                             f"(expected{access_note})"),
                    source="host",
                ))
            else:
                findings.append(Finding(
                    id=finding_id, status=Status.FAIL,
                    summary=(f"{scope}: {directive} = {actual[directive]!r}; "
                             f"expected {wanted!r}{access_note}"),
                    recommendation=f"Set the effective {directive} value to {wanted!r}.",
                    source="host",
                ))
        return findings

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if not data.get("applicable"):
            return [Finding(
                id="sshd-config-applicability", status=Status.SKIP,
                summary=data.get("skip_reason", "Effective sshd configuration does not apply."),
                source="host",
            )]
        if data.get("collection_error"):
            return [Finding(
                id="sshd-config-read", status=Status.WARN,
                summary=data["collection_error"],
                recommendation="Fix sshd configuration errors and run the check again.",
                source="host",
            )]

        sshd_policy = _sshd_policy(policy)
        global_expected = {
            key: value for key, value in (sshd_policy.get("expected") or {}).items()
            if value is not None
        }
        findings = self._scope_findings("default", data.get("default", {}), global_expected)
        policy_contexts = {
            item["name"]: item for item in sshd_policy.get("contexts", [])
        }
        for observed in data.get("contexts", []):
            name = observed["name"]
            if observed.get("error"):
                findings.append(Finding(
                    id=f"context:{name}", status=Status.WARN,
                    summary=f"Context {name}: {observed['error']}",
                    source="host",
                ))
                continue
            expected = dict(global_expected)
            expected.update({
                key: value
                for key, value in (
                    policy_contexts.get(name, {}).get("expected") or {}
                ).items()
                if value is not None
            })
            findings.extend(self._scope_findings(
                f"context-{name}", observed.get("settings", {}), expected,
            ))
            if observed.get("malformed"):
                findings.append(Finding(
                    id=f"context-{name}:parse", status=Status.WARN,
                    summary=(f"Context {name}: ignored "
                             f"{len(observed['malformed'])} malformed sshd -T line(s)."),
                    source="host",
                ))

        files = data.get("files", [])
        for item in files:
            mode = int(item["mode"], 8)
            if item["kind"] == "host-private-key":
                secure = item["uid"] == 0 and mode & 0o077 == 0
                requirement = "owned by root and inaccessible to group/other"
            else:
                secure = item["uid"] == 0 and mode & 0o022 == 0
                requirement = "owned by root and not writable by group/other"
            findings.append(Finding(
                id="file:" + item["path"].removeprefix("/etc/ssh/").replace("/", ":"),
                status=Status.PASS if secure else Status.FAIL,
                summary=(f"{item['path']}: uid {item['uid']}, gid {item['gid']}, "
                         f"mode {item['mode']}"),
                recommendation="" if secure else f"Make the file {requirement}.",
                source="host",
            ))
        paths = {item["path"] for item in files}
        if "/etc/ssh/sshd_config" not in paths:
            findings.append(Finding(
                id="file:sshd_config", status=Status.WARN,
                summary="Could not read metadata for /etc/ssh/sshd_config.",
                source="host",
            ))
        if not any(item["kind"] == "host-private-key" for item in files):
            findings.append(Finding(
                id="file:host-private-keys", status=Status.WARN,
                summary="No OpenSSH host private-key metadata was found.",
                source="host",
            ))
        if data.get("files_error"):
            findings.append(Finding(
                id="sshd-files-read", status=Status.WARN,
                summary=data["files_error"], source="host",
            ))
        if data.get("files_malformed"):
            findings.append(Finding(
                id="sshd-files-parse", status=Status.WARN,
                summary=f"Ignored {len(data['files_malformed'])} malformed stat line(s).",
                source="host",
            ))

        if data.get("malformed"):
            findings.append(Finding(
                id="sshd-config-parse", status=Status.WARN,
                summary=f"Ignored {len(data['malformed'])} malformed sshd -T line(s).",
                source="host",
            ))
        return findings or [Finding(
            id="sshd-config-inventory", status=Status.INFO,
            summary=(f"Read effective OpenSSH configuration with {data.get('runner', 'unknown')} "
                     f"for {1 + len(data.get('contexts', []))} context(s)."),
            source="host",
        )]


register(SshdConfigPlugin())
