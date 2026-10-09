from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol, runtime_checkable

from ssh_auditor.models import Evidence, Finding

if TYPE_CHECKING:
    from ssh_auditor.models import Credentials
    from ssh_auditor.store import Profile


@dataclass
class Meta:
    id: str
    version: str
    category: str
    name: str
    impact: str
    requires_auth: bool
    timeout_s: float
    privilege: str = "none"
    credential_method: str = ""
    actions: tuple[str, ...] = ()


@dataclass
class Context:
    host: str
    port: int
    policy: dict
    params: dict
    emit: Callable[[str], None]
    credentials: "Credentials | None" = None
    profile: "Profile | None" = None
    connection_sem: "asyncio.Semaphore | None" = None
    connection_limit: int = 1


@asynccontextmanager
async def connection_slot(ctx: "Context"):
    """Hold one host connection slot for the duration of a single SSH connection,
    so concurrent scans against the same device never exceed the host limit."""
    if ctx.connection_sem is None:
        yield
        return
    async with ctx.connection_sem:
        yield


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
