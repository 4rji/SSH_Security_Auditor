from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator,
)


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"
    ERROR = "ERROR"


class AuthMethod(str, Enum):
    NONE = "none"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"


_Response = Annotated[SecretStr, Field(max_length=4096)]
_Tag = Annotated[str, Field(min_length=1, max_length=64)]


class Credentials(BaseModel):
    """Write-only credentials used while a scan is running.

    SecretStr keeps values out of reprs and validation messages. ScanRequest excludes
    the complete object from serialization as a second line of defence: credentials
    must never become part of a cached result, event, export, or MCP response.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    method: AuthMethod = AuthMethod.NONE
    username: str = Field("", max_length=128)
    password: SecretStr | None = Field(
        None, max_length=4096, json_schema_extra={"writeOnly": True},
    )
    private_key: SecretStr | None = Field(
        None, max_length=262_144, json_schema_extra={"writeOnly": True},
    )
    private_key_passphrase: SecretStr | None = Field(
        None, max_length=4096, json_schema_extra={"writeOnly": True},
    )
    certificate: SecretStr | None = Field(
        None, max_length=262_144, json_schema_extra={"writeOnly": True},
    )
    keyboard_interactive_responses: list[_Response] = Field(
        default_factory=list, max_length=16, json_schema_extra={"writeOnly": True},
    )

    @field_validator("username")
    @classmethod
    def _strip_username(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _required_for_method(self) -> "Credentials":
        if self.method == AuthMethod.NONE:
            return self
        if not self.username:
            raise ValueError("username is required for the selected authentication method")
        if self.method == AuthMethod.PASSWORD and not _has_secret(self.password):
            raise ValueError("password is required for password authentication")
        if self.method == AuthMethod.PRIVATE_KEY and not _has_secret(self.private_key):
            raise ValueError("private_key is required for private-key authentication")
        if self.method == AuthMethod.CERTIFICATE:
            if not _has_secret(self.private_key):
                raise ValueError("private_key is required for certificate authentication")
            if not _has_secret(self.certificate):
                raise ValueError("certificate is required for certificate authentication")
        if (self.method == AuthMethod.KEYBOARD_INTERACTIVE
                and not self.keyboard_interactive_responses):
            raise ValueError(
                "at least one response is required for keyboard-interactive authentication"
            )
        return self

    def secret_values(self) -> tuple[str, ...]:
        """Return non-empty secret values for in-memory redaction only."""
        values = [self.password, self.private_key, self.private_key_passphrase,
                  self.certificate, *self.keyboard_interactive_responses]
        return tuple(value.get_secret_value() for value in values if _has_secret(value))


def _has_secret(value: SecretStr | None) -> bool:
    return value is not None and bool(value.get_secret_value())


class Finding(BaseModel):
    id: str
    status: Status
    summary: str
    recommendation: str = ""
    source: Literal["network", "host"] = "network"


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


class LoadParams(BaseModel):
    """Per-run parameters for the concurrency_bounded test (Phase 4).

    concurrency (max connections in flight) stays in ScanRequest.concurrency; the
    service validates these against the profile and fills the iterations default."""

    model_config = ConfigDict(extra="forbid")

    iterations: int | None = Field(None, ge=1)
    error_rate_pct: int = Field(10, ge=0, le=100)
    p95_factor: float = Field(3.0, ge=1.0, le=100.0)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    target_host: str = Field(min_length=1, max_length=253)
    port: int = Field(22, ge=1, le=65535)
    target_name: str = Field("", max_length=120)
    model: str = Field("", max_length=128)
    firmware: str = Field("", max_length=128)
    tags: list[_Tag] = Field(default_factory=list, max_length=32)
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
    # Accepted as input but deliberately absent from model_dump/model_dump_json. The
    # engine receives it directly and results have no corresponding field.
    credentials: Credentials = Field(
        default_factory=Credentials, exclude=True,
        json_schema_extra={"writeOnly": True},
    )


class ScanResult(BaseModel):
    scan_id: str
    schema_version: str = "1"
    target_host: str
    port: int
    target_name: str = ""
    model: str = ""
    firmware: str = ""
    tags: list[str] = Field(default_factory=list)
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
