from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from ssh_auditor.models import Evidence, Finding


@dataclass
class Meta:
    id: str
    version: str
    category: str
    name: str
    impact: str
    requires_auth: bool
    timeout_s: float


@dataclass
class Context:
    host: str
    port: int
    policy: dict
    params: dict
    emit: Callable[[str], None]


@runtime_checkable
class Plugin(Protocol):
    meta: Meta

    async def collect(self, ctx: Context) -> Evidence: ...

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]: ...


REGISTRY: dict[str, "Plugin"] = {}


def register(plugin: "Plugin") -> None:
    REGISTRY[plugin.meta.id] = plugin


def get(test_id: str) -> "Plugin":
    return REGISTRY[test_id]


def catalog() -> list[Meta]:
    return [p.meta for p in REGISTRY.values()]
