from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Finding(BaseModel):
    id: str
    status: Status
    summary: str
    recommendation: str = ""
    source: str = "network"


class Evidence(BaseModel):
    data: dict = Field(default_factory=dict)


class TestResult(BaseModel):
    test_id: str
    test_version: str
    category: str
    status: Status
    findings: list[Finding]
    evidence: Evidence
    duration_ms: int
    impact: str


class ScanRequest(BaseModel):
    target_host: str
    port: int = 22
    profile: str = "generico"
    tests: list[str] = Field(default_factory=list)
    policy: str = "base"
    params: dict = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    schema_version: str = "1"
    target_host: str
    port: int
    profile: str
    policy_name: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    results: list[TestResult]
    tool_version: str

    def summary(self) -> dict[Status, int]:
        out: dict[Status, int] = {}
        for r in self.results:
            out[r.status] = out.get(r.status, 0) + 1
        return out
