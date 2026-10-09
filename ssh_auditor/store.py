"""Device profiles and policies: built-in ones (read-only, shipped with the tool) plus
custom ones uploaded by engineers and shared with everyone through the server.

A custom item is stored as `<custom_dir>/<kind>/<id>.yaml` next to `<id>.meta.json`
(who uploaded it, when, and the SHA-256 of its owner token). The token is returned
only once, on upload; the uploader's browser keeps it and must present it to delete.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator,
)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAX_YAML_BYTES = 64 * 1024
EXAMPLES_DIR = Path(__file__).parent / "examples"
NOUN = {"profiles": "profile", "policies": "policy"}


class StoreError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlgorithmRule(_Strict):
    forbidden: list[str] = Field(default_factory=list)


class SshdExpected(_Strict):
    """Canonical values printed by OpenSSH's ``sshd -T``.

    The lowercase field names intentionally match the command output. A missing value
    is collected as inventory but doesn't produce a policy verdict.
    """

    passwordauthentication: Literal["yes", "no"] | None = None
    pubkeyauthentication: Literal["yes", "no"] | None = None
    kbdinteractiveauthentication: Literal["yes", "no"] | None = None
    permitrootlogin: Literal[
        "yes", "no", "prohibit-password", "without-password", "forced-commands-only"
    ] | None = None
    allowusers: list[str] | None = None
    denyusers: list[str] | None = None
    allowgroups: list[str] | None = None
    denygroups: list[str] | None = None
    maxauthtries: int | None = Field(None, ge=1, le=1024)
    logingracetime: int | None = Field(None, ge=0, le=86400)
    maxsessions: int | None = Field(None, ge=0, le=1024)
    maxstartups: str | None = Field(None, max_length=80)
    persourcepenalties: str | None = Field(None, max_length=512)
    clientaliveinterval: int | None = Field(None, ge=0, le=86400)
    clientalivecountmax: int | None = Field(None, ge=0, le=1024)
    tcpkeepalive: Literal["yes", "no"] | None = None
    unusedconnectiontimeout: str | None = Field(None, max_length=80)
    channeltimeout: str | None = Field(None, max_length=512)
    usepam: Literal["yes", "no"] | None = None

    @field_validator("allowusers", "denyusers", "allowgroups", "denygroups")
    @classmethod
    def patterns_are_bounded(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        if len(values) > 128:
            raise ValueError("at most 128 patterns are allowed")
        for value in values:
            if (not value or len(value) > 256
                    or any(c in value for c in ("\x00", "\r", "\n"))):
                raise ValueError("patterns must be non-empty single-line strings (max 256)")
        return values

    @field_validator(
        "maxstartups", "persourcepenalties", "unusedconnectiontimeout", "channeltimeout",
    )
    @classmethod
    def values_are_one_line(cls, value: str | None) -> str | None:
        if value is not None and any(c in value for c in ("\x00", "\r", "\n")):
            raise ValueError("expected values must be a single line")
        return value


class SshdContext(_Strict):
    """One synthetic connection passed to ``sshd -T -C``."""

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,47}$")
    user: str = Field(min_length=1, max_length=128)
    # These describe the simulated *client* seen by sshd, not the audited server.
    # Supplying all three works with older OpenSSH releases too.
    host: str = Field(min_length=1, max_length=253)
    addr: str = Field(min_length=1, max_length=64)
    invalid_user: bool = False
    expected: SshdExpected = Field(default_factory=SshdExpected)

    @field_validator("user", "host")
    @classmethod
    def connection_value_is_safe(cls, value: str) -> str:
        if (any(c in value for c in ("\x00", "\r", "\n", ",", "="))
                or any(c.isspace() for c in value)):
            raise ValueError(
                "connection values cannot contain whitespace, control characters, ',' or '='"
            )
        return value

    @field_validator("addr")
    @classmethod
    def address_is_an_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("addr must be an IPv4 or IPv6 address") from exc


class SshdPolicy(_Strict):
    expected: SshdExpected = Field(default_factory=SshdExpected)
    contexts: list[SshdContext] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def context_names_are_unique(self) -> "SshdPolicy":
        names = [context.name for context in self.contexts]
        if len(names) != len(set(names)):
            raise ValueError("sshd context names must be unique")
        return self


class PerformancePolicy(_Strict):
    """Thresholds for the Phase 4 memory (E) and concurrency (F) tests."""

    hash_cost_mib: int = Field(16, ge=1, le=1024)
    expected_method: str = Field("yescrypt", max_length=32)
    login_latency_limit_ms: int = Field(1500, ge=1, le=600_000)
    mem_warn_fraction: float = Field(0.75, gt=0, le=1)
    concurrency_success_floor_pct: int = Field(95, ge=0, le=100)


class Policy(_Strict):
    id: str
    name: str = ""
    description: str = ""
    kex: AlgorithmRule = Field(default_factory=AlgorithmRule)
    ciphers: AlgorithmRule = Field(default_factory=AlgorithmRule)
    macs: AlgorithmRule = Field(default_factory=AlgorithmRule)
    host_key: AlgorithmRule = Field(default_factory=AlgorithmRule)
    sshd: SshdPolicy = Field(default_factory=SshdPolicy)
    performance: PerformancePolicy = Field(default_factory=PerformancePolicy)


class Limits(_Strict):
    max_connections: int = Field(20, ge=1, le=1000)
    max_concurrency: int = Field(4, ge=1, le=64)


class Profile(_Strict):
    id: str
    name: str = ""
    description: str = ""
    shell: Literal["linux", "router-cli"] = "linux"
    safe_command: str = Field("id", min_length=1, max_length=512)
    limits: Limits = Field(default_factory=Limits)
    policy: str = "base"

    @model_validator(mode="before")
    @classmethod
    def drop_legacy_detection(cls, data):
        # Profiles used to carry model/firmware detection commands. That test was
        # removed; uploaded profiles that still have the key must keep loading.
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k != "detection"}
        return data

    @field_validator("safe_command")
    @classmethod
    def safe_command_must_be_one_line(cls, value: str) -> str:
        value = value.strip()
        if not value or any(c in value for c in ("\x00", "\r", "\n")):
            raise ValueError("safe_command must be a non-empty single line")
        return value


KINDS: dict[str, type[_Strict]] = {"profiles": Profile, "policies": Policy}


def _check_id(item_id: str) -> None:
    if not ID_RE.match(item_id or ""):
        raise StoreError(422, f"Invalid id {item_id!r}: use lowercase letters, digits, "
                              "'-' or '_' (max 48 characters).")


def parse(kind: str, text: str):
    """Validate YAML text against the kind's schema; raises StoreError(422)."""
    if len(text.encode("utf-8")) > MAX_YAML_BYTES:
        raise StoreError(413, f"File too large (max {MAX_YAML_BYTES // 1024} KB).")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise StoreError(422, f"Invalid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise StoreError(422, "The YAML must be a mapping (key: value).")
    try:
        doc = KINDS[kind].model_validate(raw)
    except ValidationError as e:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '(root)'}: {err['msg']}"
            for err in e.errors()
        )
        raise StoreError(422, f"Invalid {NOUN[kind]}: {problems}") from e
    _check_id(doc.id)
    return doc


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, kind: str, builtin_dir: str | Path, custom_dir: str | Path | None):
        self.kind = kind
        self.builtin_dir = Path(builtin_dir)
        self.custom_dir = Path(custom_dir) / kind if custom_dir else None

    # --- reading -----------------------------------------------------------------

    def _builtin_path(self, item_id: str) -> Path:
        return self.builtin_dir / f"{item_id}.yaml"

    def _custom_path(self, item_id: str) -> Path | None:
        return self.custom_dir / f"{item_id}.yaml" if self.custom_dir else None

    def _meta(self, item_id: str) -> dict:
        if not self.custom_dir:
            return {}
        try:
            return json.loads((self.custom_dir / f"{item_id}.meta.json").read_text())
        except (OSError, ValueError):
            return {}

    def _path(self, item_id: str) -> Path | None:
        _check_id(item_id)
        for p in (self._builtin_path(item_id), self._custom_path(item_id)):
            if p is not None and p.is_file():
                return p
        return None

    def text(self, item_id: str) -> str:
        p = self._path(item_id)
        if p is None:
            raise StoreError(404, f"Unknown {self._noun()}: {item_id}")
        return p.read_text()

    def load(self, item_id: str):
        doc = parse(self.kind, self.text(item_id))
        if doc.id != item_id:
            raise StoreError(422, f"{self._noun().capitalize()} file {item_id}.yaml "
                                  f"declares id '{doc.id}'; they must match.")
        return doc

    def exists(self, item_id: str) -> bool:
        try:
            return self._path(item_id) is not None
        except StoreError:
            return False

    def list(self) -> list[dict]:
        items: dict[str, dict] = {}
        dirs = [(self.builtin_dir, True)]
        if self.custom_dir:
            dirs.append((self.custom_dir, False))
        for d, builtin in dirs:
            if not d.is_dir():
                continue
            for p in sorted(d.glob("*.yaml")):
                item_id = p.stem
                if item_id in items or not ID_RE.match(item_id):
                    continue
                try:
                    doc = parse(self.kind, p.read_text())
                except StoreError:
                    continue  # a broken file never reaches the UI
                if doc.id != item_id:
                    continue
                entry = {"id": item_id, "name": doc.name or item_id,
                         "description": doc.description, "builtin": builtin}
                if isinstance(doc, Profile):
                    entry.update({
                        "policy": doc.policy,
                        "shell": doc.shell,
                        "safe_command": doc.safe_command,
                        "limits": doc.limits.model_dump(),
                    })
                if not builtin:
                    meta = self._meta(item_id)
                    entry["uploaded_by"] = meta.get("uploaded_by", "")
                    entry["uploaded_at"] = meta.get("uploaded_at", "")
                items[item_id] = entry
        return sorted(items.values(), key=lambda e: (not e["builtin"], e["id"]))

    # --- writing -----------------------------------------------------------------

    def add(self, text: str, uploaded_by: str) -> tuple[str, str]:
        """Store a new custom item. Returns (id, owner_token)."""
        if not self.custom_dir:
            raise StoreError(503, "Uploads are disabled: custom_dir is not configured.")
        doc = parse(self.kind, text)
        if self._builtin_path(doc.id).is_file():
            raise StoreError(409, f"'{doc.id}' is a built-in {self._noun()}; "
                                  "choose another id.")
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(24)
        meta = {
            "uploaded_by": (uploaded_by or "").strip()[:80],
            "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "owner_token_sha256": _token_hash(token),
        }
        final = self.custom_dir / f"{doc.id}.yaml"
        meta_final = self.custom_dir / f"{doc.id}.meta.json"
        tmp_yaml = self._write_tmp(text)
        tmp_meta = self._write_tmp(json.dumps(meta))
        try:
            # link() fails if the id already exists, so two uploads can't race.
            os.link(tmp_yaml, final)
        except FileExistsError:
            os.unlink(tmp_meta)
            raise StoreError(409, f"A {self._noun()} with id '{doc.id}' already exists.") from None
        finally:
            os.unlink(tmp_yaml)
        os.replace(tmp_meta, meta_final)
        return doc.id, token

    def delete(self, item_id: str, owner_token: str) -> None:
        _check_id(item_id)
        if self._builtin_path(item_id).is_file():
            raise StoreError(403, f"'{item_id}' is built-in and can't be deleted.")
        path = self._custom_path(item_id)
        if path is None or not path.is_file():
            raise StoreError(404, f"Unknown {self._noun()}: {item_id}")
        expected = self._meta(item_id).get("owner_token_sha256", "")
        if not (owner_token and expected
                and hmac.compare_digest(_token_hash(owner_token), expected)):
            raise StoreError(403, "Only the engineer who uploaded it can delete it "
                                  "(from the same browser).")
        path.unlink(missing_ok=True)
        (self.custom_dir / f"{item_id}.meta.json").unlink(missing_ok=True)

    def _write_tmp(self, content: str) -> str:
        fd, tmp = tempfile.mkstemp(dir=self.custom_dir, prefix=".upload-")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return tmp

    def _noun(self) -> str:
        return NOUN[self.kind]


def example_text(kind: str) -> str:
    return (EXAMPLES_DIR / f"{NOUN[kind]}.example.yaml").read_text()
