from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 7284
    allow_networks: list[str] = field(default_factory=list)
    cache_ttl_s: int = 86400
    # Background scans (started from MCP) that may run at the same time.
    max_active_scans: int = 10
    policies_dir: str = "config/policies"
    profiles_dir: str = "config/profiles"
    # Writable directory for the profiles and policies engineers upload (shared by all).
    # Empty = uploads disabled.
    custom_dir: str = "data"


def load_config(path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    known = {k: v for k, v in raw.items() if k in Config.__dataclass_fields__}
    # Under systemd, StateDirectory= sets $STATE_DIRECTORY (/var/lib/ssh-auditor): the only
    # writable place when ProtectSystem=strict, so uploads go there unless configured.
    if "custom_dir" not in known and os.environ.get("STATE_DIRECTORY"):
        known["custom_dir"] = os.environ["STATE_DIRECTORY"].split(":")[0]
    return Config(**known)


def _resolve(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        return [ai[4][0] for ai in socket.getaddrinfo(host, None)]
    except Exception:  # noqa: BLE001
        return []


def resolve_allowed_target(cfg: Config, host: str) -> str | None:
    """Resolve once and return the concrete allowed address used for the scan."""
    if not cfg.allow_networks:
        return None
    nets = [ipaddress.ip_network(n, strict=False) for n in cfg.allow_networks]
    for ip in _resolve(host):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in n for n in nets):
            return str(addr)
    return None


def target_allowed(cfg: Config, host: str) -> bool:
    """Compatibility predicate for callers which only need an allow/deny answer."""
    return resolve_allowed_target(cfg, host) is not None
