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
    target_host: str = Field(min_length=1, max_length=253)
    port: int = Field(22, ge=1, le=65535)
    profile: str = "generic"
    tests: list[str] = Field(default_factory=list)
    # Empty = the device profile's own policy.
    policy: str = ""
    params: dict = Field(default_factory=dict)
    # Optional name of the engineer who runs the scan (the "Your name" field).
    run_by: str = Field("", max_length=80)
    # Connections this scan may open at once. Empty = the profile's limit; above it the
    # server rejects the request, whether it comes from the web or from MCP. Phase 4
    # concurrency tests read it.
    concurrency: int | None = Field(None, ge=1)
    # Tests with medium or high impact only run with this set explicitly.
    confirm_impact: bool = False


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
    run_by: str = ""

    def summary(self) -> dict[Status, int]:
        out: dict[Status, int] = {}
        for r in self.results:
            out[r.status] = out.get(r.status, 0) + 1
        return out
