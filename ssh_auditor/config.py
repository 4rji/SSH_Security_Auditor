from __future__ import annotations

import ipaddress
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
    policies_dir: str = "config/policies"
    profiles_dir: str = "config/profiles"


def load_config(path) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    known = {k: v for k, v in raw.items() if k in Config.__dataclass_fields__}
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


def target_allowed(cfg: Config, host: str) -> bool:
    if not cfg.allow_networks:
        return False
    nets = [ipaddress.ip_network(n, strict=False) for n in cfg.allow_networks]
    for ip in _resolve(host):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in n for n in nets):
            return True
    return False


def load_policy(cfg: Config, name: str) -> dict:
    path = Path(cfg.policies_dir) / f"{name}.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def load_profile(cfg: Config, name: str) -> dict:
    path = Path(cfg.profiles_dir) / f"{name}.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def list_policies(cfg: Config) -> list[str]:
    d = Path(cfg.policies_dir)
    return sorted(p.stem for p in d.glob("*.yaml")) if d.exists() else []


def list_profiles(cfg: Config) -> list[str]:
    d = Path(cfg.profiles_dir)
    return sorted(p.stem for p in d.glob("*.yaml")) if d.exists() else []
