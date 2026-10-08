# Fase 1 — Base y negociación SSH — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un servicio interno que, sin autenticar contra el equipo, lee la negociación SSH de un objetivo (algoritmos, host keys, métodos de autenticación, Terrapin, KEX post-cuántico), la evalúa contra una política, la muestra en una web con progreso en tiempo real y permite exportar y comparar ejecuciones.

**Architecture:** Un motor sin estado en disco recibe un `ScanRequest` y produce un `ScanResult`. Cada prueba es un plugin con `collect()` (produce evidencia) y `evaluate()` (función pura evidencia+política → hallazgos). La web (FastAPI) y, en la Fase 2, el MCP, son dos envoltorios del mismo motor. Los resultados viven en una caché en RAM con TTL y en el navegador; nunca se escriben en disco.

**Tech Stack:** Python 3.13, asyncssh 2.24 (conexiones y, en tests, servidor SSH en proceso), FastAPI + Uvicorn, SSE, Pydantic v2, PyYAML, pytest + pytest-asyncio. Frontend HTML/JS sin compilación.

**Spec:** `instrucciones.md` (v2, en la raíz del repo)

## Global Constraints

- Python 3.13 exacto (el de Debian 13). El módulo `crypt` no existe; no usarlo.
- El servidor **nunca** escribe credenciales ni resultados en disco. Caché solo en RAM.
- Las credenciales no aparecen en `ScanResult`, exportaciones ni logs.
- Toda prueba de red tiene timeout y es cancelable con `asyncio`.
- Allowlist de redes destino obligatoria: si está vacía, se rechaza todo objetivo.
- Lo observado por red y lo leído dentro del equipo se marcan con `source: "network" | "host"`. Fase 1 es todo `network`.
- Estados válidos: `PASS`, `WARN`, `FAIL`, `INFO`, `SKIP`, `ERROR`. Un resultado inconcluso es `WARN` o `SKIP`, nunca `PASS`/`FAIL` falso.
- Export JSON lleva `schema_version` (empieza en `"1"`).
- Los algoritmos del servidor se leen del `KEXINIT`; no se implementan algoritmos débiles para detectarlos.
- Puerto por defecto de la web: `7284`. Solo red interna, sin token.

## Review Focus

- **Objetivo fuera de la allowlist o allowlist vacía** → `POST /scans` responde 403 y no se abre ninguna conexión. (Task 10)
- **El objetivo no acepta TCP / timeout de conexión** → la prueba de conectividad es `FAIL`/`ERROR` con motivo, y negociación queda `SKIP`, sin excepción sin capturar. (Task 11)
- **KEXINIT malformado o truncado** (no es SSH, responde basura, cierra a mitad) → el parser lanza `KexInitError`, la prueba es `ERROR` con motivo, el proceso no cae. (Task 3)
- **Importar un JSON inválido o de `schema_version` distinta** en comparar → error 422 claro, sin traza al usuario. (Task 9)
- **Dos exportaciones con versiones de plugin/política distintas** → la comparación igual se produce y avisa de la diferencia de versiones. (Task 8)

---

## File Structure

- `ssh_auditor/models.py` — enums y modelos Pydantic (`Status`, `Finding`, `Evidence`, `TestResult`, `ScanRequest`, `ScanResult`).
- `ssh_auditor/kexinit.py` — parser puro del paquete SSH_MSG_KEXINIT + helpers Terrapin/PQ.
- `ssh_auditor/plugins/base.py` — `Plugin` protocol, `Meta`, `Context`, `REGISTRY`.
- `ssh_auditor/plugins/connectivity.py` — prueba A.
- `ssh_auditor/plugins/negotiation.py` — prueba B.
- `ssh_auditor/policy.py` — carga YAML y `evaluate`.
- `ssh_auditor/engine/runner.py` — orquesta un scan, aplica límites, emite eventos.
- `ssh_auditor/engine/cache.py` — caché en RAM con TTL.
- `ssh_auditor/engine/limits.py` — semáforos por objetivo.
- `ssh_auditor/compare.py` — diff entre dos `ScanResult`.
- `ssh_auditor/export.py` — JSON/HTML/CSV.
- `ssh_auditor/config.py` — carga `config.yaml`, perfiles y políticas; allowlist.
- `ssh_auditor/web/app.py` — rutas FastAPI, SSE, estáticos.
- `ssh_auditor/web/static/{index.html,app.js,claude.html}` — UI.
- `config/config.example.yaml`, `config/policies/base.yaml`, `config/profiles/generico.yaml`.
- `deploy/ssh-auditor.service`, `deploy/install.sh`.
- `tests/conftest.py` — servidor SSH asyncssh en proceso como fixture.
- `tests/...` — un archivo por módulo.

---

### Task 1: Modelos y estados

**Files:**
- Create: `ssh_auditor/__init__.py`, `ssh_auditor/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `class Status(str, Enum)`: `PASS WARN FAIL INFO SKIP ERROR`.
  - `Finding(id: str, status: Status, summary: str, recommendation: str = "", source: str = "network")`
  - `Evidence(data: dict)` — JSON-serializable.
  - `TestResult(test_id: str, test_version: str, category: str, status: Status, findings: list[Finding], evidence: Evidence, duration_ms: int, impact: str)`
  - `ScanRequest(target_host: str, port: int = 22, profile: str = "generico", tests: list[str], policy: str, params: dict = {})` — sin credenciales en Fase 1.
  - `ScanResult(scan_id: str, schema_version: str = "1", target_host: str, port: int, profile: str, policy_name: str, started_at: datetime, finished_at: datetime | None, status: str, results: list[TestResult], tool_version: str)`
  - `ScanResult.summary() -> dict[Status, int]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from datetime import datetime, timezone
from ssh_auditor.models import Status, Finding, Evidence, TestResult, ScanResult

def test_scan_result_summary_counts_by_status():
    def tr(status):
        return TestResult(test_id="t", test_version="1", category="B",
                          status=status, findings=[], evidence=Evidence(data={}),
                          duration_ms=1, impact="none")
    sr = ScanResult(scan_id="s1", target_host="10.0.0.5", port=22, profile="generico",
                    policy_name="base", started_at=datetime.now(timezone.utc),
                    finished_at=None, status="running",
                    results=[tr(Status.PASS), tr(Status.PASS), tr(Status.FAIL)],
                    tool_version="0.1.0")
    assert sr.schema_version == "1"
    assert sr.summary()[Status.PASS] == 2
    assert sr.summary()[Status.FAIL] == 1

def test_finding_defaults_source_network():
    f = Finding(id="f1", status=Status.PASS, summary="ok")
    assert f.source == "network"
    assert f.recommendation == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_models.py -v`
Expected: FAIL (ImportError: cannot import name 'Status').

- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/models.py
from __future__ import annotations
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

class Status(str, Enum):
    PASS = "PASS"; WARN = "WARN"; FAIL = "FAIL"
    INFO = "INFO"; SKIP = "SKIP"; ERROR = "ERROR"

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_models.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit** — (el usuario hace git; dejar el working tree listo, no ejecutar git)

---

### Task 2: Parser KEXINIT — caso correcto

**Files:**
- Create: `ssh_auditor/kexinit.py`
- Test: `tests/test_kexinit.py`

**Interfaces:**
- Produces:
  - `class KexInitError(Exception)`
  - `@dataclass KexInit` con campos: `kex: list[str]`, `server_host_key: list[str]`, `enc_c2s: list[str]`, `enc_s2c: list[str]`, `mac_c2s: list[str]`, `mac_s2c: list[str]`, `comp_c2s: list[str]`, `comp_s2c: list[str]`, `first_kex_follows: bool`.
  - `parse_kexinit(payload: bytes) -> KexInit` — `payload` es el cuerpo SSH_MSG_KEXINIT **sin** la cabecera de longitud/padding del paquete binario: empieza en el byte de tipo de mensaje `0x14` (20).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_kexinit.py
import struct
from ssh_auditor.kexinit import parse_kexinit, KexInit, KexInitError
import pytest

def _namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b

def _build(kex, hostkey, enc, mac, comp, first_follows=False) -> bytes:
    body = b"\x14"                      # SSH_MSG_KEXINIT
    body += b"\x00" * 16               # cookie
    for nl in (kex, hostkey, enc, enc, mac, mac, comp, comp, "", ""):
        body += _namelist(nl)
    body += b"\x01" if first_follows else b"\x00"
    body += struct.pack(">I", 0)       # reserved
    return body

def test_parse_basic_kexinit():
    payload = _build(
        kex="mlkem768x25519-sha256,curve25519-sha256",
        hostkey="ssh-ed25519,rsa-sha2-512",
        enc="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        mac="hmac-sha2-256-etm@openssh.com",
        comp="none",
    )
    k = parse_kexinit(payload)
    assert k.kex == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert k.server_host_key == ["ssh-ed25519", "rsa-sha2-512"]
    assert k.enc_s2c == ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
    assert k.comp_c2s == ["none"]
    assert k.first_kex_follows is False
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_kexinit.py::test_parse_basic_kexinit -v` → FAIL (ImportError).

- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/kexinit.py
from __future__ import annotations
import struct
from dataclasses import dataclass

SSH_MSG_KEXINIT = 20

class KexInitError(Exception):
    pass

@dataclass
class KexInit:
    kex: list[str]
    server_host_key: list[str]
    enc_c2s: list[str]
    enc_s2c: list[str]
    mac_c2s: list[str]
    mac_s2c: list[str]
    comp_c2s: list[str]
    comp_s2c: list[str]
    first_kex_follows: bool

def _read_namelist(buf: bytes, off: int) -> tuple[list[str], int]:
    if off + 4 > len(buf):
        raise KexInitError("truncado leyendo longitud de name-list")
    (length,) = struct.unpack_from(">I", buf, off)
    off += 4
    if off + length > len(buf):
        raise KexInitError("truncado leyendo name-list")
    raw = buf[off:off + length].decode("ascii", "replace")
    off += length
    names = [n for n in raw.split(",") if n] if raw else []
    return names, off

def parse_kexinit(payload: bytes) -> KexInit:
    if len(payload) < 1 + 16:
        raise KexInitError("payload demasiado corto")
    if payload[0] != SSH_MSG_KEXINIT:
        raise KexInitError(f"no es KEXINIT (tipo {payload[0]})")
    off = 1 + 16  # tipo + cookie
    lists = []
    for _ in range(10):
        names, off = _read_namelist(payload, off)
        lists.append(names)
    if off + 1 > len(payload):
        raise KexInitError("truncado leyendo first_kex_follows")
    first = payload[off] != 0
    return KexInit(
        kex=lists[0], server_host_key=lists[1],
        enc_c2s=lists[2], enc_s2c=lists[3],
        mac_c2s=lists[4], mac_s2c=lists[5],
        comp_c2s=lists[6], comp_s2c=lists[7],
        first_kex_follows=first,
    )
```

- [ ] **Step 4: Run** same test → PASS.
- [ ] **Step 5: Commit** (working tree listo; sin git).

---

### Task 3: Parser KEXINIT — entradas malformadas

**Files:**
- Modify: `ssh_auditor/kexinit.py` (ya robusto; esta task fija el contrato con tests)
- Test: `tests/test_kexinit.py`

**Interfaces:** Consumes `parse_kexinit`, `KexInitError` de Task 2.

- [ ] **Step 1: Write the failing tests**

```python
def test_rejects_wrong_message_type():
    with pytest.raises(KexInitError):
        parse_kexinit(b"\x15" + b"\x00" * 16 + struct.pack(">I", 0) * 10)

def test_rejects_truncated_namelist():
    bad = b"\x14" + b"\x00" * 16 + struct.pack(">I", 1000)  # dice 1000 bytes, no hay
    with pytest.raises(KexInitError):
        parse_kexinit(bad)

def test_rejects_empty_payload():
    with pytest.raises(KexInitError):
        parse_kexinit(b"")
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_kexinit.py -v` → los nuevos PASAN ya (parser robusto). Si alguno falla, corregir `kexinit.py` hasta que pase.
- [ ] **Step 3:** Sin cambios de implementación esperados.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_kexinit.py -v` → PASS (todos).
- [ ] **Step 5: Commit** (sin git).

---

### Task 4: Detección Terrapin y KEX post-cuántico

**Files:**
- Modify: `ssh_auditor/kexinit.py`
- Test: `tests/test_posture.py`

**Interfaces:**
- Produces:
  - `is_terrapin_vulnerable(k: KexInit) -> bool` — vulnerable si **no** aparece `kex-strict-s-v00@openssh.com` en `k.kex` **y** el cifrado negociable incluye `chacha20-poly1305@openssh.com` o algún cifrado `*-cbc` combinado con un MAC `*-etm@openssh.com`. Evalúa sobre `enc_s2c`/`mac_s2c`.
  - `has_pq_kex(k: KexInit) -> bool` — `True` si `k.kex` contiene `mlkem768x25519-sha256` o `sntrup761x25519-sha512`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_posture.py
from ssh_auditor.kexinit import KexInit, is_terrapin_vulnerable, has_pq_kex

def _k(kex, enc, mac):
    return KexInit(kex=kex, server_host_key=["ssh-ed25519"],
                   enc_c2s=enc, enc_s2c=enc, mac_c2s=mac, mac_s2c=mac,
                   comp_c2s=["none"], comp_s2c=["none"], first_kex_follows=False)

def test_terrapin_vulnerable_chacha_without_strict():
    k = _k(["curve25519-sha256"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    assert is_terrapin_vulnerable(k) is True

def test_terrapin_safe_with_strict_kex():
    k = _k(["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
           ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    assert is_terrapin_vulnerable(k) is False

def test_terrapin_vulnerable_cbc_etm():
    k = _k(["curve25519-sha256"], ["aes256-cbc"], ["hmac-sha2-256-etm@openssh.com"])
    assert is_terrapin_vulnerable(k) is True

def test_terrapin_safe_gcm_only():
    k = _k(["curve25519-sha256"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256-etm@openssh.com"])
    assert is_terrapin_vulnerable(k) is False

def test_pq_kex_detected():
    assert has_pq_kex(_k(["mlkem768x25519-sha256"], ["aes256-gcm@openssh.com"], [])) is True
    assert has_pq_kex(_k(["curve25519-sha256"], ["aes256-gcm@openssh.com"], [])) is False
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_posture.py -v` → FAIL (ImportError).
- [ ] **Step 3: Write minimal implementation** (añadir a `kexinit.py`):

```python
STRICT_KEX_MARKER = "kex-strict-s-v00@openssh.com"
PQ_KEX = {"mlkem768x25519-sha256", "sntrup761x25519-sha512"}

def has_pq_kex(k: KexInit) -> bool:
    return any(a in PQ_KEX for a in k.kex)

def is_terrapin_vulnerable(k: KexInit) -> bool:
    if STRICT_KEX_MARKER in k.kex:
        return False
    enc = set(k.enc_s2c)
    mac = set(k.mac_s2c)
    if "chacha20-poly1305@openssh.com" in enc:
        return True
    has_cbc = any(a.endswith("-cbc") for a in enc)
    has_etm = any(a.endswith("-etm@openssh.com") for a in mac)
    return has_cbc and has_etm
```

- [ ] **Step 4: Run** → PASS (5 passed).
- [ ] **Step 5: Commit** (sin git).

---

### Task 5: Contrato de plugin y registro

**Files:**
- Create: `ssh_auditor/plugins/__init__.py`, `ssh_auditor/plugins/base.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Produces:
  - `@dataclass Meta(id, version, category, name, impact, requires_auth: bool, timeout_s: float)`
  - `@dataclass Context(host: str, port: int, policy: dict, params: dict, emit: Callable[[str], None])`
  - `class Plugin(Protocol)`: atributo `meta: Meta`; `async def collect(self, ctx) -> Evidence`; `def evaluate(self, evidence, policy: dict) -> list[Finding]`.
  - `REGISTRY: dict[str, Plugin]` y `register(plugin)`; `get(test_id) -> Plugin`; `catalog() -> list[Meta]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_registry.py
from ssh_auditor.plugins.base import Meta, register, get, catalog, REGISTRY
from ssh_auditor.models import Evidence, Finding, Status

class _Dummy:
    meta = Meta(id="dummy", version="1", category="B", name="Dummy",
                impact="none", requires_auth=False, timeout_s=5.0)
    async def collect(self, ctx): return Evidence(data={"ok": True})
    def evaluate(self, evidence, policy): return [Finding(id="dummy", status=Status.INFO, summary="x")]

def test_register_and_get():
    register(_Dummy())
    assert get("dummy").meta.name == "Dummy"
    assert any(m.id == "dummy" for m in catalog())
```

- [ ] **Step 2: Run** → FAIL (ImportError).
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/plugins/base.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable
from ssh_auditor.models import Evidence, Finding

@dataclass
class Meta:
    id: str; version: str; category: str; name: str
    impact: str; requires_auth: bool; timeout_s: float

@dataclass
class Context:
    host: str; port: int; policy: dict; params: dict
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
```

```python
# ssh_auditor/plugins/__init__.py
from . import connectivity, negotiation  # noqa: F401  (auto-registro)
```
(Comentar los imports hasta que existan esos módulos; descomentar en Task 6 y 7.)

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 6: Fixture de servidor SSH y plugin de conectividad (prueba A)

**Files:**
- Create: `tests/conftest.py`, `ssh_auditor/plugins/connectivity.py`
- Test: `tests/test_connectivity.py`

**Interfaces:**
- Consumes `Meta`, `Context`, `register` (Task 5); `Evidence`, `Finding`, `Status` (Task 1).
- Produces: fixture `ssh_server` → `(host, port)` de un servidor asyncssh en proceso con banner conocido; `ConnectivityPlugin` con `meta.id = "connectivity"`.
- Produces evidencia: `{"tcp_open": bool, "connect_ms": int, "banner": str|None}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/conftest.py
import asyncio, asyncssh, pytest, pytest_asyncio

class _Server(asyncssh.SSHServer):
    def begin_auth(self, username): return False  # sin auth: permite ninguna

@pytest_asyncio.fixture
async def ssh_server():
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        server_version="SSH-2.0-TestServer_1.0",
    )
    sock = server.sockets[0]
    host, port = sock.getsockname()[0], sock.getsockname()[1]
    yield host, port
    server.close()
    await server.wait_closed()
```

```python
# tests/test_connectivity.py
import pytest
from ssh_auditor.plugins.connectivity import ConnectivityPlugin
from ssh_auditor.plugins.base import Context
from ssh_auditor.models import Status

@pytest.mark.asyncio
async def test_connectivity_reaches_server(ssh_server):
    host, port = ssh_server
    p = ConnectivityPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    assert ev.data["tcp_open"] is True
    assert ev.data["banner"].startswith("SSH-2.0")
    findings = p.evaluate(ev, {})
    assert any(f.status == Status.PASS for f in findings)

@pytest.mark.asyncio
async def test_connectivity_refused_port():
    p = ConnectivityPlugin()
    ev = await p.collect(Context(host="127.0.0.1", port=1, policy={}, params={}, emit=lambda m: None))
    assert ev.data["tcp_open"] is False
    findings = p.evaluate(ev, {})
    assert any(f.status in (Status.FAIL, Status.ERROR) for f in findings)
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_connectivity.py -v` → FAIL (ImportError).
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/plugins/connectivity.py
from __future__ import annotations
import asyncio, time
from ssh_auditor.plugins.base import Meta, Context, register
from ssh_auditor.models import Evidence, Finding, Status

class ConnectivityPlugin:
    meta = Meta(id="connectivity", version="1", category="A",
                name="Conectividad TCP y banner", impact="none",
                requires_auth=False, timeout_s=10.0)

    async def collect(self, ctx: Context) -> Evidence:
        data = {"tcp_open": False, "connect_ms": None, "banner": None}
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ctx.host, ctx.port), timeout=ctx.meta_timeout()
            )
        except Exception as e:  # noqa: BLE001
            data["error"] = f"{type(e).__name__}: {e}"
            return Evidence(data=data)
        data["tcp_open"] = True
        data["connect_ms"] = int((time.monotonic() - t0) * 1000)
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            data["banner"] = line.decode("ascii", "replace").strip() or None
        except Exception:  # noqa: BLE001
            data["banner"] = None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        return Evidence(data=data)

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        d = evidence.data
        if not d["tcp_open"]:
            return [Finding(id="tcp", status=Status.FAIL,
                            summary=f"No se pudo abrir TCP {d.get('error','')}".strip(),
                            recommendation="Verificar red, puerto y allowlist.")]
        out = [Finding(id="tcp", status=Status.PASS,
                       summary=f"TCP abierto en {d['connect_ms']} ms")]
        if d.get("banner"):
            out.append(Finding(id="banner", status=Status.INFO, summary=d["banner"]))
        return out
```
Nota: `ctx.meta_timeout()` no existe; usar un timeout fijo. Reemplazar por `timeout=10.0`. Añadir `register(ConnectivityPlugin())` al final del módulo.

- [ ] **Step 4: Run** → PASS (2 passed).
- [ ] **Step 5: Commit** (sin git).

---

### Task 7: Plugin de negociación (prueba B)

**Files:**
- Create: `ssh_auditor/plugins/negotiation.py`
- Test: `tests/test_negotiation.py`

**Interfaces:**
- Consumes `parse_kexinit`, `is_terrapin_vulnerable`, `has_pq_kex` (Tasks 2–4); `asyncssh.get_server_host_key` para fingerprints; `Meta/Context/register`.
- Produces: `NegotiationPlugin` con `meta.id = "negotiation"`.
- Evidencia: `{"kex": [...], "server_host_key": [...], "enc_s2c": [...], "mac_s2c": [...], "comp_s2c": [...], "host_key_fingerprints": {alg: "SHA256:..."}, "terrapin": bool, "pq_kex": bool, "banner": str}`.
- `collect` abre un socket, envía el ident string del cliente, lee el banner y el primer paquete del servidor, extrae el payload KEXINIT (quitando `packet_length`(4) + `padding_length`(1), tomando `payload` según RFC 4253) y lo pasa a `parse_kexinit`. Para fingerprints usa `asyncssh.get_server_host_key(host, port, server_host_key_algs=[alg])` por cada alg de `server_host_key` y `.get_fingerprint()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_negotiation.py
import pytest
from ssh_auditor.plugins.negotiation import NegotiationPlugin
from ssh_auditor.plugins.base import Context
from ssh_auditor.models import Status

@pytest.mark.asyncio
async def test_negotiation_reads_algorithms(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    assert len(ev.data["kex"]) > 0
    assert len(ev.data["server_host_key"]) > 0
    assert any(fp.startswith("SHA256:") for fp in ev.data["host_key_fingerprints"].values())
    assert "terrapin" in ev.data and "pq_kex" in ev.data

@pytest.mark.asyncio
async def test_negotiation_policy_flags_prohibited(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    # política que prohíbe exactamente el primer kex ofrecido
    policy = {"kex": {"prohibidos": [ev.data["kex"][0]]}}
    findings = p.evaluate(ev, policy)
    assert any(f.status == Status.FAIL for f in findings)
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_negotiation.py -v` → FAIL.
- [ ] **Step 3: Write minimal implementation** — leer KEXINIT crudo del servidor:

```python
# ssh_auditor/plugins/negotiation.py
from __future__ import annotations
import asyncio, struct
import asyncssh
from ssh_auditor.plugins.base import Meta, Context, register
from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.kexinit import parse_kexinit, is_terrapin_vulnerable, has_pq_kex

CLIENT_IDENT = b"SSH-2.0-SSHAuditor_0.1\r\n"

async def _read_ident_and_kexinit(host: str, port: int, timeout: float):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(CLIENT_IDENT)
        await writer.drain()
        banner = None
        # el servidor puede enviar líneas previas; el ident es la que empieza por "SSH-"
        for _ in range(50):
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise ConnectionError("servidor cerró antes del ident")
            text = line.decode("ascii", "replace").strip()
            if text.startswith("SSH-"):
                banner = text
                break
        # primer paquete binario: uint32 packet_length, byte padding_length, payload, padding
        header = await asyncio.wait_for(reader.readexactly(5), timeout)
        (pkt_len,) = struct.unpack(">I", header[:4])
        pad_len = header[4]
        body = await asyncio.wait_for(reader.readexactly(pkt_len - 1), timeout)
        payload = body[: len(body) - pad_len]
        return banner, payload
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

class NegotiationPlugin:
    meta = Meta(id="negotiation", version="1", category="B",
                name="Negociación SSH", impact="none",
                requires_auth=False, timeout_s=15.0)

    async def collect(self, ctx: Context) -> Evidence:
        banner, payload = await _read_ident_and_kexinit(ctx.host, ctx.port, self.meta.timeout_s)
        k = parse_kexinit(payload)
        fps: dict[str, str] = {}
        for alg in k.server_host_key:
            try:
                key = await asyncio.wait_for(
                    asyncssh.get_server_host_key(ctx.host, ctx.port, server_host_key_algs=[alg]),
                    timeout=self.meta.timeout_s)
                if key is not None:
                    fps[alg] = key.get_fingerprint("sha256")
            except Exception:  # noqa: BLE001
                continue
        return Evidence(data={
            "banner": banner,
            "kex": k.kex, "server_host_key": k.server_host_key,
            "enc_s2c": k.enc_s2c, "mac_s2c": k.mac_s2c, "comp_s2c": k.comp_s2c,
            "host_key_fingerprints": fps,
            "terrapin": is_terrapin_vulnerable(k),
            "pq_kex": has_pq_kex(k),
        })

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        d = evidence.data
        out: list[Finding] = []
        prohibidos = set((policy.get("kex") or {}).get("prohibidos", []))
        for a in d["kex"]:
            if a in prohibidos:
                out.append(Finding(id=f"kex-prohibido:{a}", status=Status.FAIL,
                                   summary=f"KEX prohibido ofrecido: {a}",
                                   recommendation="Deshabilitar en sshd_config."))
        out.append(Finding(id="terrapin",
                           status=Status.FAIL if d["terrapin"] else Status.PASS,
                           summary="Vulnerable a Terrapin (CVE-2023-48795)" if d["terrapin"]
                                   else "No vulnerable a Terrapin",
                           recommendation="Habilitar kex-strict y revisar cifrados." if d["terrapin"] else ""))
        out.append(Finding(id="pq-kex",
                           status=Status.PASS if d["pq_kex"] else Status.WARN,
                           summary="Ofrece KEX post-cuántico" if d["pq_kex"]
                                   else "Sin KEX post-cuántico",
                           recommendation="" if d["pq_kex"] else "Actualizar OpenSSH a 9.9+/10."))
        for alg, fp in d["host_key_fingerprints"].items():
            out.append(Finding(id=f"hostkey:{alg}", status=Status.INFO, summary=f"{alg} {fp}"))
        return out

register(NegotiationPlugin())
```
Luego descomentar los imports en `ssh_auditor/plugins/__init__.py`.

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_negotiation.py -v` → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 8: Comparación de dos ScanResult

**Files:**
- Create: `ssh_auditor/compare.py`
- Test: `tests/test_compare.py`

**Interfaces:**
- Produces: `compare(a: ScanResult, b: ScanResult) -> dict` con:
  - `tests`: lista de `{test_id, change: "Mejoró|Empeoró|Igual|Nueva|Desaparecida", status_a, status_b}`.
  - `evidence_diff`: por test, `added`/`removed` de `kex`, `server_host_key`, y cambio de `host_key_fingerprints`.
  - `warnings`: lista; incluye aviso si `tool_version` o versiones de plugin difieren.
  - Orden de severidad para `change`: FAIL(0) < WARN(1) < INFO/SKIP(2) < PASS(3); `b` con índice mayor que `a` ⇒ "Mejoró".

- [ ] **Step 1: Write the failing test**

```python
# tests/test_compare.py
from datetime import datetime, timezone
from ssh_auditor.models import ScanResult, TestResult, Evidence, Status
from ssh_auditor.compare import compare

def _sr(results, tool="0.1.0"):
    return ScanResult(scan_id="x", target_host="h", port=22, profile="p",
                      policy_name="base", started_at=datetime.now(timezone.utc),
                      finished_at=None, status="done", results=results, tool_version=tool)

def _tr(tid, status, ev=None):
    return TestResult(test_id=tid, test_version="1", category="B", status=status,
                      findings=[], evidence=Evidence(data=ev or {}), duration_ms=1, impact="none")

def test_compare_detects_improvement_and_new():
    a = _sr([_tr("negotiation", Status.FAIL)])
    b = _sr([_tr("negotiation", Status.PASS), _tr("connectivity", Status.PASS)])
    res = compare(a, b)
    by = {t["test_id"]: t for t in res["tests"]}
    assert by["negotiation"]["change"] == "Mejoró"
    assert by["connectivity"]["change"] == "Nueva"

def test_compare_evidence_hostkey_change_and_version_warning():
    a = _sr([_tr("negotiation", Status.PASS, {"host_key_fingerprints": {"ssh-ed25519": "SHA256:AAA"}, "kex": ["x"]})], tool="0.1.0")
    b = _sr([_tr("negotiation", Status.PASS, {"host_key_fingerprints": {"ssh-ed25519": "SHA256:BBB"}, "kex": ["x", "y"]})], tool="0.2.0")
    res = compare(a, b)
    diff = res["evidence_diff"]["negotiation"]
    assert diff["host_key_changed"] is True
    assert "y" in diff["kex"]["added"]
    assert any("versión" in w.lower() or "version" in w.lower() for w in res["warnings"])
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/compare.py
from __future__ import annotations
from ssh_auditor.models import ScanResult, Status

_RANK = {Status.FAIL: 0, Status.ERROR: 0, Status.WARN: 1,
         Status.INFO: 2, Status.SKIP: 2, Status.PASS: 3}

def _change(sa: Status, sb: Status) -> str:
    ra, rb = _RANK[sa], _RANK[sb]
    if rb > ra: return "Mejoró"
    if rb < ra: return "Empeoró"
    return "Igual"

def _list_diff(la, lb):
    sa, sb = set(la or []), set(lb or [])
    return {"added": sorted(sb - sa), "removed": sorted(sa - sb)}

def compare(a: ScanResult, b: ScanResult) -> dict:
    ra = {r.test_id: r for r in a.results}
    rb = {r.test_id: r for r in b.results}
    tests = []
    for tid in sorted(set(ra) | set(rb)):
        if tid in ra and tid in rb:
            change = _change(ra[tid].status, rb[tid].status)
            sa, sb = ra[tid].status, rb[tid].status
        elif tid in rb:
            change, sa, sb = "Nueva", None, rb[tid].status
        else:
            change, sa, sb = "Desaparecida", ra[tid].status, None
        tests.append({"test_id": tid, "change": change,
                      "status_a": sa.value if sa else None,
                      "status_b": sb.value if sb else None})
    evidence_diff = {}
    for tid in set(ra) & set(rb):
        da, db = ra[tid].evidence.data, rb[tid].evidence.data
        entry = {}
        for field in ("kex", "server_host_key", "enc_s2c", "mac_s2c"):
            if field in da or field in db:
                entry[field] = _list_diff(da.get(field), db.get(field))
        fa = da.get("host_key_fingerprints") or {}
        fb = db.get("host_key_fingerprints") or {}
        entry["host_key_changed"] = bool(fa) and bool(fb) and fa != fb
        evidence_diff[tid] = entry
    warnings = []
    if a.tool_version != b.tool_version:
        warnings.append(f"Versión de herramienta distinta: {a.tool_version} vs {b.tool_version}")
    for tid in set(ra) & set(rb):
        if ra[tid].test_version != rb[tid].test_version:
            warnings.append(f"Versión del plugin '{tid}' distinta: {ra[tid].test_version} vs {rb[tid].test_version}")
    return {"tests": tests, "evidence_diff": evidence_diff, "warnings": warnings}
```

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 9: Exportación e importación JSON/HTML/CSV

**Files:**
- Create: `ssh_auditor/export.py`
- Test: `tests/test_export.py`

**Interfaces:**
- Produces:
  - `to_json(sr: ScanResult) -> str` (usa `model_dump_json`, sin credenciales — Fase 1 no las tiene).
  - `from_json(text: str) -> ScanResult` — valida `schema_version == "1"`, lanza `ValueError` si no.
  - `to_csv(sr: ScanResult) -> str` — columnas: `test_id,category,status,summary`.
  - `to_html(sr: ScanResult) -> str` — HTML autocontenido con tabla por categoría.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_export.py
import pytest
from datetime import datetime, timezone
from ssh_auditor.models import ScanResult, TestResult, Evidence, Finding, Status
from ssh_auditor.export import to_json, from_json, to_csv, to_html

def _sr():
    tr = TestResult(test_id="negotiation", test_version="1", category="B", status=Status.PASS,
                    findings=[Finding(id="terrapin", status=Status.PASS, summary="ok")],
                    evidence=Evidence(data={"kex": ["x"]}), duration_ms=5, impact="none")
    return ScanResult(scan_id="s1", target_host="10.0.0.5", port=22, profile="p",
                      policy_name="base", started_at=datetime.now(timezone.utc),
                      finished_at=datetime.now(timezone.utc), status="done",
                      results=[tr], tool_version="0.1.0")

def test_json_roundtrip():
    sr = _sr()
    back = from_json(to_json(sr))
    assert back.scan_id == "s1"
    assert back.results[0].evidence.data["kex"] == ["x"]

def test_from_json_rejects_wrong_schema():
    bad = to_json(_sr()).replace('"schema_version":"1"', '"schema_version":"9"')
    with pytest.raises(ValueError):
        from_json(bad)

def test_csv_and_html_contain_test():
    sr = _sr()
    assert "negotiation" in to_csv(sr)
    html = to_html(sr)
    assert "<html" in html.lower() and "negotiation" in html
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/export.py
from __future__ import annotations
import csv, html, io, json
from ssh_auditor.models import ScanResult

def to_json(sr: ScanResult) -> str:
    return sr.model_dump_json()

def from_json(text: str) -> ScanResult:
    raw = json.loads(text)
    if raw.get("schema_version") != "1":
        raise ValueError(f"schema_version no soportado: {raw.get('schema_version')!r}")
    return ScanResult.model_validate(raw)

def to_csv(sr: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["test_id", "category", "status", "summary"])
    for r in sr.results:
        summary = "; ".join(f.summary for f in r.findings) or r.status.value
        w.writerow([r.test_id, r.category, r.status.value, summary])
    return buf.getvalue()

def to_html(sr: ScanResult) -> str:
    rows = []
    for r in sr.results:
        for f in r.findings:
            rows.append(f"<tr><td>{html.escape(r.category)}</td>"
                        f"<td>{html.escape(r.test_id)}</td>"
                        f"<td>{html.escape(f.status.value)}</td>"
                        f"<td>{html.escape(f.summary)}</td></tr>")
    body = "\n".join(rows)
    return (f"<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            f"<title>SSH Auditor — {html.escape(sr.target_host)}</title></head>"
            f"<body><h1>{html.escape(sr.target_host)}:{sr.port}</h1>"
            f"<table border='1'><thead><tr><th>Categoría</th><th>Prueba</th>"
            f"<th>Estado</th><th>Resumen</th></tr></thead><tbody>{body}</tbody></table></body></html>")
```

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 10: Config, allowlist y carga de políticas

**Files:**
- Create: `ssh_auditor/config.py`, `config/config.example.yaml`, `config/policies/base.yaml`, `config/profiles/generico.yaml`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces:
  - `load_config(path) -> Config` con `listen_host`, `listen_port`, `allow_networks: list[str]`, `cache_ttl_s`, `policies_dir`, `profiles_dir`.
  - `target_allowed(cfg, host: str) -> bool` — `False` si `allow_networks` vacío; compara contra CIDRs con `ipaddress`. Hostnames no-IP ⇒ `False` salvo que el CIDR contenga su IP resuelta (Fase 1: resolver con `socket.getaddrinfo`, y si falla, `False`).
  - `load_policy(cfg, name) -> dict`, `load_profile(cfg, name) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from ssh_auditor.config import load_config, target_allowed

def test_empty_allowlist_denies(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("listen_port: 7284\nallow_networks: []\n")
    cfg = load_config(cfg_file)
    assert target_allowed(cfg, "10.0.0.5") is False

def test_cidr_allows_and_denies(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("allow_networks: ['10.0.0.0/24']\n")
    cfg = load_config(cfg_file)
    assert target_allowed(cfg, "10.0.0.5") is True
    assert target_allowed(cfg, "192.168.1.5") is False
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/config.py
from __future__ import annotations
import ipaddress, socket
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
    return Config(**{k: v for k, v in raw.items() if k in Config.__dataclass_fields__})

def _resolve(host: str):
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
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in nets):
            return True
    return False

def load_policy(cfg: Config, name: str) -> dict:
    return yaml.safe_load((Path(cfg.policies_dir) / f"{name}.yaml").read_text()) or {}

def load_profile(cfg: Config, name: str) -> dict:
    return yaml.safe_load((Path(cfg.profiles_dir) / f"{name}.yaml").read_text()) or {}
```

`config/config.example.yaml`:
```yaml
listen_host: 0.0.0.0
listen_port: 7284
allow_networks:
  - 10.0.0.0/24      # ajustar a la red de laboratorio; vacío = rechaza todo
cache_ttl_s: 86400
policies_dir: config/policies
profiles_dir: config/profiles
```

`config/policies/base.yaml`:
```yaml
nombre: base
kex:
  prohibidos: [diffie-hellman-group1-sha1, diffie-hellman-group14-sha1]
  requerido_pq: mlkem768x25519-sha256   # ausencia => WARN
cifrados:
  prohibidos: [3des-cbc, aes128-cbc, aes192-cbc, aes256-cbc]
host_key:
  prohibidos: [ssh-rsa, ssh-dss]
```

`config/profiles/generico.yaml`:
```yaml
id: generico
nombre: Genérico
shell: linux
comando_inocuo: id
limites:
  conexiones_max: 50
  concurrencia_max: 4
politica: base
```

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 11: Motor de scan, límites y caché

**Files:**
- Create: `ssh_auditor/engine/__init__.py`, `ssh_auditor/engine/cache.py`, `ssh_auditor/engine/limits.py`, `ssh_auditor/engine/runner.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `REGISTRY/get` (Task 5), plugins (6–7), `ScanRequest/ScanResult/TestResult` (Task 1), `Context` (Task 5).
- Produces:
  - `TTLCache(ttl_s)`: `put(scan_id, sr)`, `get(scan_id) -> ScanResult|None`, expira por tiempo.
  - `LimitRegistry`: `semaphore(host, limit) -> asyncio.Semaphore` (uno por host, memoizado).
  - `async run_scan(req: ScanRequest, policy: dict, tool_version: str, limit: int, cache: TTLCache, on_event=None) -> ScanResult`. Ejecuta cada test seleccionado dentro del semáforo del host; un fallo de un plugin produce `TestResult` con status `ERROR` y no aborta los demás; mide `duration_ms`; guarda en caché; emite eventos `started/test_done/finished` por `on_event`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_engine.py
import pytest
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.models import ScanRequest, Status
import ssh_auditor.plugins  # fuerza el registro

@pytest.mark.asyncio
async def test_run_scan_negotiation(ssh_server):
    host, port = ssh_server
    cache = TTLCache(ttl_s=60)
    events = []
    req = ScanRequest(target_host=host, port=port, profile="generico",
                      tests=["connectivity", "negotiation"], policy="base")
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4,
                        cache=cache, on_event=lambda e: events.append(e))
    assert sr.status == "done"
    ids = {r.test_id for r in sr.results}
    assert ids == {"connectivity", "negotiation"}
    assert all(r.status != Status.ERROR for r in sr.results)
    assert cache.get(sr.scan_id) is not None
    assert any(e["type"] == "finished" for e in events)

@pytest.mark.asyncio
async def test_run_scan_unknown_test_is_error(ssh_server):
    host, port = ssh_server
    req = ScanRequest(target_host=host, port=port, tests=["no_existe"], policy="base")
    sr = await run_scan(req, policy={}, tool_version="0.1.0", limit=4, cache=TTLCache(60))
    assert sr.results[0].status == Status.ERROR
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation**

```python
# ssh_auditor/engine/cache.py
from __future__ import annotations
import time
from ssh_auditor.models import ScanResult

class TTLCache:
    def __init__(self, ttl_s: int):
        self.ttl_s = ttl_s
        self._d: dict[str, tuple[float, ScanResult]] = {}
    def put(self, scan_id: str, sr: ScanResult) -> None:
        self._d[scan_id] = (time.monotonic(), sr)
    def get(self, scan_id: str):
        item = self._d.get(scan_id)
        if not item:
            return None
        ts, sr = item
        if time.monotonic() - ts > self.ttl_s:
            self._d.pop(scan_id, None)
            return None
        return sr
    def ids(self) -> list[str]:
        return list(self._d.keys())
```

```python
# ssh_auditor/engine/limits.py
from __future__ import annotations
import asyncio

class LimitRegistry:
    def __init__(self):
        self._sems: dict[str, asyncio.Semaphore] = {}
    def semaphore(self, host: str, limit: int) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(limit)
        return self._sems[host]
```

```python
# ssh_auditor/engine/runner.py
from __future__ import annotations
import asyncio, time, uuid
from datetime import datetime, timezone
from ssh_auditor.models import ScanRequest, ScanResult, TestResult, Evidence, Finding, Status
from ssh_auditor.plugins.base import Context, REGISTRY
from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.limits import LimitRegistry

_LIMITS = LimitRegistry()

async def _run_one(test_id, ctx, sem) -> TestResult:
    plugin = REGISTRY.get(test_id)
    if plugin is None:
        return TestResult(test_id=test_id, test_version="0", category="?",
                          status=Status.ERROR, findings=[Finding(id=test_id,
                          status=Status.ERROR, summary=f"Prueba desconocida: {test_id}")],
                          evidence=Evidence(data={}), duration_ms=0, impact="none")
    t0 = time.monotonic()
    try:
        async with sem:
            ev = await asyncio.wait_for(plugin.collect(ctx), timeout=plugin.meta.timeout_s)
        findings = plugin.evaluate(ev, ctx.policy)
        status = _rollup(findings)
    except Exception as e:  # noqa: BLE001
        ev = Evidence(data={"error": f"{type(e).__name__}: {e}"})
        findings = [Finding(id=test_id, status=Status.ERROR, summary=str(e))]
        status = Status.ERROR
    return TestResult(test_id=test_id, test_version=plugin.meta.version,
                      category=plugin.meta.category, status=status, findings=findings,
                      evidence=ev, duration_ms=int((time.monotonic()-t0)*1000),
                      impact=plugin.meta.impact)

def _rollup(findings) -> Status:
    order = [Status.ERROR, Status.FAIL, Status.WARN, Status.PASS, Status.INFO, Status.SKIP]
    present = {f.status for f in findings}
    for s in order:
        if s in present:
            return s
    return Status.SKIP

async def run_scan(req: ScanRequest, policy: dict, tool_version: str, limit: int,
                   cache: TTLCache, on_event=None) -> ScanResult:
    def emit(ev):
        if on_event:
            on_event(ev)
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc)
    emit({"type": "started", "scan_id": scan_id, "tests": req.tests})
    sem = _LIMITS.semaphore(req.target_host, limit)
    results: list[TestResult] = []
    for tid in req.tests:
        ctx = Context(host=req.target_host, port=req.port, policy=policy,
                      params=req.params, emit=lambda m: emit({"type": "log", "msg": m}))
        tr = await _run_one(tid, ctx, sem)
        results.append(tr)
        emit({"type": "test_done", "test_id": tid, "status": tr.status.value})
    sr = ScanResult(scan_id=scan_id, target_host=req.target_host, port=req.port,
                    profile=req.profile, policy_name=req.policy, started_at=started,
                    finished_at=datetime.now(timezone.utc), status="done",
                    results=results, tool_version=tool_version)
    cache.put(scan_id, sr)
    emit({"type": "finished", "scan_id": scan_id, "summary": {k.value: v for k, v in sr.summary().items()}})
    return sr
```

- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 12: API FastAPI con allowlist, SSE y export

**Files:**
- Create: `ssh_auditor/web/__init__.py`, `ssh_auditor/web/app.py`, `ssh_auditor/__main__.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: `create_app(cfg: Config) -> FastAPI` con:
  - `GET /api/v1/tests` → catálogo (de `catalog()`).
  - `GET /api/v1/profiles` → nombres de perfiles y políticas en los dirs.
  - `POST /api/v1/scans` → 403 si `target_allowed` es `False`; si no, corre `run_scan` y devuelve el `ScanResult`.
  - `GET /api/v1/scans/{id}` → 404 si no está en caché; si no, el `ScanResult`.
  - `GET /api/v1/scans/{id}/export?format=json|csv|html`.
  - `POST /api/v1/compare` → body `{a: ScanResult, b: ScanResult}` o `{a_id, b_id}` desde caché; 422 si un JSON es inválido.
  - Monta estáticos de `web/static` en `/`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_api.py
import pytest
from httpx import ASGITransport, AsyncClient
from ssh_auditor.web.app import create_app
from ssh_auditor.config import Config

def _app(host, port):
    cfg = Config(allow_networks=["127.0.0.0/8"], policies_dir="config/policies",
                 profiles_dir="config/profiles")
    return create_app(cfg)

@pytest.mark.asyncio
async def test_tests_catalog_and_scan_and_export(ssh_server):
    import ssh_auditor.plugins  # registro
    host, port = ssh_server
    app = _app(host, port)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/v1/tests")
        assert r.status_code == 200 and any(t["id"] == "negotiation" for t in r.json())
        r = await c.post("/api/v1/scans", json={"target_host": host, "port": port,
            "tests": ["connectivity", "negotiation"], "policy": "base"})
        assert r.status_code == 200
        sid = r.json()["scan_id"]
        r = await c.get(f"/api/v1/scans/{sid}/export?format=csv")
        assert r.status_code == 200 and "negotiation" in r.text

@pytest.mark.asyncio
async def test_scan_denied_outside_allowlist():
    app = create_app(Config(allow_networks=["10.0.0.0/24"],
                            policies_dir="config/policies", profiles_dir="config/profiles"))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={"target_host": "192.168.1.1",
            "tests": ["connectivity"], "policy": "base"})
        assert r.status_code == 403
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_api.py -v` → FAIL.
- [ ] **Step 3: Write minimal implementation** — FastAPI con rutas; carga de política por nombre con fallback `{}`; SSE con `StreamingResponse` sobre una cola `asyncio.Queue` alimentada por `on_event`; estáticos con `StaticFiles`. (Código completo en el módulo; seguir las firmas de arriba.)
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 13: Frontend (4 pasos, progreso, exportar, comparar)

**Files:**
- Create: `ssh_auditor/web/static/index.html`, `ssh_auditor/web/static/app.js`, `ssh_auditor/web/static/claude.html`
- Test: `tests/test_static.py` (humo: los archivos existen y referencian los endpoints)

**Interfaces:** Consume la API de Task 12. Sin credenciales en Fase 1 (solo pruebas sin login).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_static.py
from pathlib import Path
def test_static_files_reference_api():
    base = Path("ssh_auditor/web/static")
    idx = (base / "index.html").read_text()
    js = (base / "app.js").read_text()
    assert "SSH Security Auditor" in idx
    assert "/api/v1/scans" in js
    assert "sessionStorage" in js   # resultados en navegador
    assert (base / "claude.html").exists()
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation** — `index.html` con los 4 pasos (Objetivo, Credenciales deshabilitado en Fase 1, Pruebas con checkboxes desde `/api/v1/tests`, Ejecución); `app.js` que lanza el scan, pinta resultados, guarda en `sessionStorage`, botones Exportar (descarga JSON/HTML/CSV) y Comparar (carga dos JSON y llama `/api/v1/compare`); `claude.html` con el comando `claude mcp add` y nota de Fase 2.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** (sin git).

---

### Task 14: Empaquetado y servicio systemd

**Files:**
- Create: `pyproject.toml`, `requirements.txt` (con hashes), `deploy/ssh-auditor.service`, `deploy/install.sh`, `README.md`
- Test: `tests/test_smoke_cli.py`

**Interfaces:** `python -m ssh_auditor` arranca Uvicorn con `create_app(load_config(...))`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smoke_cli.py
import importlib
def test_main_module_importable():
    m = importlib.import_module("ssh_auditor.__main__")
    assert hasattr(m, "main")
```

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Write minimal implementation** — `__main__.py` con `main()` que lee `SSH_AUDITOR_CONFIG` (default `/etc/ssh-auditor/config.yaml`, fallback `config/config.example.yaml`) y llama `uvicorn.run`. `deploy/ssh-auditor.service`:

```ini
[Unit]
Description=SSH Security Auditor (interno)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sshauditor
Group=sshauditor
WorkingDirectory=/opt/ssh-auditor
Environment=SSH_AUDITOR_CONFIG=/etc/ssh-auditor/config.yaml
ExecStart=/opt/ssh-auditor/.venv/bin/python -m ssh_auditor
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=
MemoryMax=1G

[Install]
WantedBy=multi-user.target
```

`deploy/install.sh`: crea usuario `sshauditor`, copia a `/opt/ssh-auditor`, crea venv, `pip install -r requirements.txt`, copia `config/config.example.yaml` a `/etc/ssh-auditor/config.yaml` si no existe, instala y habilita la unidad. (Sin ejecutar git ni arrancar nada automáticamente.)

- [ ] **Step 4: Run** `.venv/bin/pytest -q` (toda la suite) → PASS.
- [ ] **Step 5: Commit** (sin git).

---

## Notas de ejecución

- Ejecutar siempre con el venv del repo: `.venv/bin/pytest`, `.venv/bin/python`.
- El usuario gestiona git; dejar el working tree ordenado y **no** ejecutar comandos git.
- Las credenciales y el login quedan para la Fase 3; en Fase 1 el paso "Credenciales" de la UI está deshabilitado.
- El MCP (Fase 2) reutilizará `run_scan`, `compare`, `TTLCache` y `catalog()` sin cambios.
