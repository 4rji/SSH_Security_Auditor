"""Device profiles and policies: built-in ones (read-only, shipped with the tool) plus
custom ones uploaded by engineers and shared with everyone through the server.

A custom item is stored as `<custom_dir>/<kind>/<id>.yaml` next to `<id>.meta.json`
(who uploaded it, when, and the SHA-256 of its owner token). The token is returned
only once, on upload; the uploader's browser keeps it and must present it to delete.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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


class Policy(_Strict):
    id: str
    name: str = ""
    description: str = ""
    kex: AlgorithmRule = Field(default_factory=AlgorithmRule)
    ciphers: AlgorithmRule = Field(default_factory=AlgorithmRule)
    macs: AlgorithmRule = Field(default_factory=AlgorithmRule)
    host_key: AlgorithmRule = Field(default_factory=AlgorithmRule)


class Limits(_Strict):
    max_connections: int = Field(20, ge=1, le=1000)
    max_concurrency: int = Field(4, ge=1, le=64)


class Profile(_Strict):
    id: str
    name: str = ""
    description: str = ""
    shell: Literal["linux", "router-cli"] = "linux"
    safe_command: str = "id"
    limits: Limits = Field(default_factory=Limits)
    policy: str = "base"


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
                    entry["policy"] = doc.policy
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
