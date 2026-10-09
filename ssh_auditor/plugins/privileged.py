"""Shared discovery of a trusted OpenSSH ``sshd`` on an authenticated connection.

Both the effective-configuration test (D) and the memory test (E) need to run
``sshd -T`` as root/sudo. Extracting the discovery keeps a single, safe implementation:
the binary must be a root-owned, non-writable system executable before it is run with
elevated privileges.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# These shell helpers live in sshd_config; importing them here (and never the other way
# at module top) keeps the dependency one-directional. sshd_config imports resolve_sshd
# lazily inside its method, so there is no import cycle.
from ssh_auditor.plugins.sshd_config import _command, _safe_text


@dataclass
class SshdTarget:
    path: str
    prefix: list[str]
    runner: str
    version: str
    system: str


@dataclass
class SkipReason:
    reason: str
    extra: dict = field(default_factory=dict)


async def resolve_sshd(run, *, profile_id: str):
    """Locate and vet ``sshd`` on an authenticated session.

    ``run(command, timeout_s)`` runs one bounded command and returns a CommandResult.
    Returns an SshdTarget on success, or a SkipReason (its ``extra`` never includes
    ``profile``; the caller adds it) describing why the test does not apply.
    """
    try:
        uname = await run("uname -s", 5.0)
    except Exception as exc:  # noqa: BLE001 - absence of a Linux shell is applicability
        return SkipReason(f"Could not confirm a Linux shell: {type(exc).__name__}")
    system = _safe_text(uname.stdout, 80) if uname.exit_status == 0 else ""
    if uname.truncated or uname.exit_status != 0 or system != "Linux":
        detail = system or _safe_text(uname.stderr, 120)
        return SkipReason(
            f"Remote shell is not Linux ({detail}); effective sshd configuration "
            "does not apply.")

    find = await run("PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v sshd", 5.0)
    path = find.stdout.strip().splitlines()[0] if find.stdout.strip() else ""
    if (find.truncated or find.exit_status != 0 or not path.startswith("/")
            or any(c.isspace() for c in path)):
        return SkipReason("OpenSSH sshd was not found on the remote Linux system.",
                          {"system": system})

    binary_stat = await run(
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin "
        + _command(["stat", "-Lc", "%u\t%a", "--", path]), 5.0)
    stat_parts = binary_stat.stdout.strip().split("\t")
    trusted_binary = (
        binary_stat.exit_status == 0 and not binary_stat.truncated
        and len(stat_parts) == 2 and stat_parts[0] == "0"
        and bool(re.fullmatch(r"[0-7]{3,4}", stat_parts[1]))
        and int(stat_parts[1], 8) & 0o022 == 0
    )
    if not trusted_binary:
        return SkipReason(
            "The discovered sshd executable is not a root-owned, non-writable "
            "system binary; refusing to run it with elevated privileges.",
            {"system": system, "sshd_path": path})

    version_result = await run(_command([path, "-V"]), 5.0)
    version = _safe_text(f"{version_result.stdout} {version_result.stderr}", 160)
    if "openssh" not in version.lower():
        return SkipReason(
            f"The remote sshd executable is not OpenSSH ({version}).",
            {"system": system})

    uid_result = await run("id -u", 5.0)
    uid = uid_result.stdout.strip()
    root = uid_result.exit_status == 0 and uid == "0"
    prefix = [] if root else ["sudo", "-n", "--"]
    runner = "root" if root else "sudo-n"
    if not root:
        sudo_check = await run(_command([*prefix, "true"]), 5.0)
        if sudo_check.exit_status != 0 or sudo_check.truncated:
            return SkipReason(
                "Reading effective sshd configuration requires root or passwordless sudo.",
                {"system": system, "sshd_path": path, "version": version, "runner": runner})

    return SshdTarget(path=path, prefix=prefix, runner=runner, version=version,
                      system=system)


async def effective_sshd(run, target: SshdTarget, extra_args=()):
    """Run ``sshd -T [extra_args]`` with the resolved prefix (root or sudo -n)."""
    argv = [*target.prefix, target.path, "-T", *extra_args]
    return await run(_command(argv), 15.0)
