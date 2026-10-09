# Fase 4 — Memoria yescrypt y concurrencia acotada — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir las pruebas E (memoria yescrypt por cálculo) y F (concurrencia acotada con parada automática) y una página "Load testing" que las usa, reutilizando la tubería de escaneo existente.

**Architecture:** Dos plugins nuevos (`memory`, `concurrency`) que pasan por `run_scan` → cache → SSE → export/compare como el resto. El tope de conexiones por host pasa a contarse por conexión (no por prueba) para que F lo respete. La página nueva reutiliza el endpoint de escaneo y un módulo JS compartido.

**Tech Stack:** Python 3.13, asyncssh, FastAPI, pydantic v2, pytest/pytest-asyncio; JS vanilla en `ssh_auditor/web/static`.

**Spec:** `docs/superpowers/specs/2026-10-09-fase4-memoria-concurrencia-design.md`

## Global Constraints

- **Git lo lleva el usuario.** NO hay pasos de commit en este plan; cada tarea termina con la suite en verde. No correr ningún comando `git`.
- **Sin `.venv` en el repo.** Antes de empezar, crear uno en el scratchpad (ver "Entorno") y usar su `pytest`. A lo largo del plan, `pytest` = `<venv>/bin/python -m pytest -p no:cacheprovider`.
- **Credenciales nunca en evidencia/eventos/export.** Toda excepción que cruce el borde de un plugin se convierte en un resumen sin texto de la excepción (patrón ya usado en `authentication.py`). No copiar `stderr`/mensajes de excepción crudos a `Evidence`/`Finding`.
- **`extra="forbid"`** en los modelos pydantic del proyecto (`_Strict`, `ScanRequest`, `Credentials`): todo campo nuevo se declara explícitamente.
- **Tope de concurrencia del perfil** (`profile.max_concurrency`) lo hace cumplir el servidor; ninguna petición (web o MCP) puede superarlo.
- Copy de UI en inglés (como el resto de `index.html`); comentarios de código en el idioma del archivo vecino.

## Review Focus

- **F con `iterations` por encima de `max_connections`** → el servicio debe rechazar con 422 antes de abrir nada (cubierto en Tarea 3).
- **F cuando el equipo rechaza la credencial en el login base** → SKIP/rejected limpio, sin lanzar la ráfaga (cubierto en Tarea 6).
- **E sin root ni sudo** (no puede leer `sshd -T`) → el campo queda en `errors` y el peor caso no se evalúa, no ERROR del test (cubierto en Tarea 5).
- **F que dispara la parada por p95 con la primera muestra lenta** → la parada por p95 solo aplica tras ≥10 ciclos; antes solo cortan error/bloqueo (cubierto en Tarea 6).
- **Dos F concurrentes contra el mismo host** → juntas nunca superan `max_concurrency` conexiones (cubierto en Tarea 1 y Tarea 6).

---

## Entorno (una sola vez, antes de la Tarea 1)

- [ ] **Crear el venv de pruebas en el scratchpad**

```bash
SP="$CLAUDE_SCRATCHPAD"   # p.ej. /tmp/claude-.../scratchpad ; si no está seteada, usar la ruta del scratchpad de la sesión
python3 -m venv --without-pip "$SP/venv"
curl -sSfL -o "$SP/get-pip.py" https://bootstrap.pypa.io/get-pip.py
"$SP/venv/bin/python" -I "$SP/get-pip.py" -q
"$SP/venv/bin/python" -I -m pip install -q -r requirements.txt "pytest>=9" "pytest-asyncio>=1.4" "httpx>=0.28"
```

- [ ] **Comprobar verde de base**

Run: `"$SP/venv/bin/python" -m pytest -q -p no:cacheprovider`
Expected: PASS (161 passed al momento de escribir este plan).

A partir de aquí, `pytest` en los pasos significa `"$SP/venv/bin/python" -m pytest -p no:cacheprovider`.

---

## Task 1: Motor — tope de conexiones por conexión, no por prueba

Hoy `_run_one` toma un slot del semáforo por host para toda la prueba. F abre muchas conexiones dentro de una prueba, así que el conteo debe moverse a cada conexión. Se expone el semáforo y el límite en el `Context` y se adquiere alrededor de cada conexión real.

**Files:**
- Modify: `ssh_auditor/plugins/base.py` (dataclass `Context`)
- Modify: `ssh_auditor/engine/runner.py` (`_run_one`, construcción de `Context` en `run_scan`)
- Modify: `ssh_auditor/plugins/authentication.py` (`_open_with_method` adquiere el semáforo)
- Test: `tests/test_limits_context.py` (nuevo)

**Interfaces:**
- Produces: `Context.connection_sem: "asyncio.Semaphore | None" = None` y `Context.connection_limit: int = 1`. Un helper `plugins.base.connection_slot(ctx)` (async context manager) que adquiere `ctx.connection_sem` si existe, o no hace nada si es `None`.

- [ ] **Step 1: Test de que el slot limita conexiones concurrentes**

```python
# tests/test_limits_context.py
import asyncio
import pytest
from ssh_auditor.plugins.base import Context, connection_slot


def _ctx(sem):
    return Context(host="h", port=22, policy={}, params={},
                   emit=lambda _m: None, connection_sem=sem, connection_limit=2)


@pytest.mark.asyncio
async def test_connection_slot_never_exceeds_limit():
    sem = asyncio.Semaphore(2)
    live = 0
    peak = 0

    async def one():
        nonlocal live, peak
        async with connection_slot(_ctx(sem)):
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.01)
            live -= 1

    await asyncio.gather(*(one() for _ in range(10)))
    assert peak <= 2


@pytest.mark.asyncio
async def test_connection_slot_is_noop_without_semaphore():
    async with connection_slot(_ctx(None)):
        pass  # must not raise
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_limits_context.py -v`
Expected: FAIL (`ImportError: cannot import name 'connection_slot'`).

- [ ] **Step 3: Añadir campos al Context y el helper**

En `ssh_auditor/plugins/base.py`, añadir a los imports `from contextlib import asynccontextmanager` y `import asyncio`; extender el dataclass y añadir el helper:

```python
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
```

- [ ] **Step 4: Correr y ver pasar**

Run: `pytest tests/test_limits_context.py -v`
Expected: PASS.

- [ ] **Step 5: `_run_one` ya no envuelve toda la prueba; `run_scan` pasa el semáforo al Context**

En `ssh_auditor/engine/runner.py`:

En `_run_one`, quitar el `async with sem:` que envuelve `collect` (dejar solo el `asyncio.wait_for`):

```python
    t0 = time.monotonic()
    try:
        ev = await asyncio.wait_for(plugin.collect(ctx), timeout=plugin.meta.timeout_s)
        findings = plugin.evaluate(ev, ctx.policy)
        status = _rollup(findings)
```

En `run_scan`, al construir cada `Context`, pasar el semáforo y el límite (la variable `sem` y `limit` ya existen en esa función):

```python
        ctx = Context(
            host=concrete_host, port=req.port, policy=policy, params=req.params,
            emit=lambda m: emit({"type": "log", "msg": m}),
            credentials=req.credentials, profile=profile,
            connection_sem=sem, connection_limit=limit,
        )
```

- [ ] **Step 6: Cada conexión de autenticación adquiere el slot**

En `ssh_auditor/plugins/authentication.py`, dentro de `_open_with_method`, envolver la conexión con el slot. Añadir el import `from ssh_auditor.plugins.base import Context, Meta, register, connection_slot` y cambiar el final de la función:

```python
    async with connection_slot(ctx):
        async with asyncssh.connect(**options) as connection:
            yield connection
```

- [ ] **Step 7: Suite completa en verde**

Run: `pytest -q`
Expected: PASS (los 161 previos siguen verdes; el conteo por conexión no cambia su resultado porque cada test de auth abre una sola conexión).

---

## Task 2: Política — bloque `performance` con los umbrales de Fase 4

**Files:**
- Modify: `ssh_auditor/store.py` (nuevo `_Strict` `PerformancePolicy`, campo en `Policy`)
- Modify: `config/policies/base.yaml`
- Test: `tests/test_phase4_policy.py` (nuevo)

**Interfaces:**
- Produces: `Policy.performance: PerformancePolicy` con campos `hash_cost_mib:int=16`, `expected_method:str="yescrypt"`, `login_latency_limit_ms:int=1500`, `mem_warn_fraction:float=0.75`, `concurrency_success_floor_pct:int=95`. En el `dict` de política que recibe un plugin, está bajo la clave `"performance"`.

- [ ] **Step 1: Test de defaults y de que YAML los acepta**

```python
# tests/test_phase4_policy.py
from ssh_auditor.store import Policy, parse


def test_performance_defaults():
    p = Policy.model_validate({"id": "x"})
    assert p.performance.hash_cost_mib == 16
    assert p.performance.expected_method == "yescrypt"
    assert p.performance.login_latency_limit_ms == 1500
    assert p.performance.mem_warn_fraction == 0.75
    assert p.performance.concurrency_success_floor_pct == 95


def test_performance_from_yaml():
    text = ("id: hard\nperformance:\n  hash_cost_mib: 32\n"
            "  login_latency_limit_ms: 800\n  concurrency_success_floor_pct: 90\n")
    p = parse("policies", text)
    assert p.performance.hash_cost_mib == 32
    assert p.performance.login_latency_limit_ms == 800
    assert p.performance.concurrency_success_floor_pct == 90
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_phase4_policy.py -v`
Expected: FAIL (`performance` no existe en `Policy`).

- [ ] **Step 3: Definir `PerformancePolicy` y añadirlo a `Policy`**

En `ssh_auditor/store.py`, cerca de `class Limits(_Strict)`:

```python
class PerformancePolicy(_Strict):
    hash_cost_mib: int = Field(16, ge=1, le=1024)
    expected_method: str = Field("yescrypt", max_length=32)
    login_latency_limit_ms: int = Field(1500, ge=1, le=600_000)
    mem_warn_fraction: float = Field(0.75, gt=0, le=1)
    concurrency_success_floor_pct: int = Field(95, ge=0, le=100)
```

En `class Policy(_Strict)`, añadir el campo:

```python
    performance: PerformancePolicy = Field(default_factory=PerformancePolicy)
```

- [ ] **Step 4: Correr y ver pasar**

Run: `pytest tests/test_phase4_policy.py -v`
Expected: PASS.

- [ ] **Step 5: Dejar los valores explícitos en la política base**

Añadir al final de `config/policies/base.yaml`:

```yaml
performance:
  hash_cost_mib: 16
  expected_method: yescrypt
  login_latency_limit_ms: 1500
  mem_warn_fraction: 0.75
  concurrency_success_floor_pct: 95
```

- [ ] **Step 6: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 3: Parámetros de carga — `LoadParams` validado en el servicio

**Files:**
- Modify: `ssh_auditor/models.py` (nuevo `LoadParams`)
- Modify: `ssh_auditor/service.py` (helper puro `normalize_load_params` + llamada en `admit`)
- Test: `tests/test_load_params.py` (nuevo)

**Interfaces:**
- Produces: `models.LoadParams` con `iterations:int|None=None`, `error_rate_pct:int=10` (0–100), `p95_factor:float=3` (1–100). `service.normalize_load_params(raw_load: dict, max_connections: int) -> dict` (puro; lanza `ScanRejected(422)` si inválido o si `iterations > max_connections`; rellena el default a `min(50, max_connections)`). `concurrency` sigue en `ScanRequest.concurrency`. El plugin F lee los valores efectivos desde `ctx.params["load"]` y `ctx.connection_limit`.
- Consumes: `admit` ya tiene el `profile` cargado; llama al helper y guarda el resultado en `req.params["load"]`.

- [ ] **Step 1: Test del helper puro (sin construir el servicio)**

```python
# tests/test_load_params.py
import pytest
from ssh_auditor.service import ScanRejected, normalize_load_params


def test_iterations_default_is_capped_to_profile():
    # generic max_connections = 20 → default iterations min(50, 20) = 20
    assert normalize_load_params({}, 20)["iterations"] == 20
    assert normalize_load_params({}, 100)["iterations"] == 50


def test_iterations_above_max_connections_is_rejected():
    with pytest.raises(ScanRejected) as exc:
        normalize_load_params({"iterations": 999}, 20)
    assert "iterations" in str(exc.value)


def test_invalid_field_is_rejected():
    with pytest.raises(ScanRejected):
        normalize_load_params({"error_rate_pct": 999}, 20)


def test_defaults_are_filled():
    out = normalize_load_params({}, 20)
    assert out["error_rate_pct"] == 10 and out["p95_factor"] == 3.0
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_load_params.py -v`
Expected: FAIL (`cannot import name 'normalize_load_params'`).

- [ ] **Step 3: Definir `LoadParams`**

En `ssh_auditor/models.py`:

```python
class LoadParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iterations: int | None = Field(None, ge=1)
    error_rate_pct: int = Field(10, ge=0, le=100)
    p95_factor: float = Field(3.0, ge=1.0, le=100.0)
```

- [ ] **Step 4: Helper puro en `service.py` + llamada en `admit`**

En `ssh_auditor/service.py`, a nivel de módulo:

```python
def normalize_load_params(raw_load: dict, max_connections: int) -> dict:
    from ssh_auditor.models import LoadParams  # local import avoids a cycle
    try:
        load = LoadParams.model_validate(raw_load or {})
    except Exception as exc:  # pydantic ValidationError, etc.
        raise ScanRejected(422, "Invalid load parameters.") from exc
    iterations = load.iterations if load.iterations is not None else min(50, max_connections)
    if iterations > max_connections:
        raise ScanRejected(
            422, f"iterations {iterations} exceeds the profile's max_connections "
                 f"({max_connections}).")
    return {**load.model_dump(), "iterations": iterations}
```

Dentro de `admit`, después de cargar `profile` y antes de devolver `Admitted`, normalizar y reescribir `req` (el `Admitted(req=req, ...)` que ya se devuelve debe usar este `req`):

```python
        normalized_params = {**(req.params or {}),
                             "load": normalize_load_params((req.params or {}).get("load", {}),
                                                           profile.limits.max_connections)}
        req = req.model_copy(update={"params": normalized_params})
```

- [ ] **Step 5: Correr y ver pasar**

Run: `pytest tests/test_load_params.py -v`
Expected: PASS.

- [ ] **Step 6: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 4: Helper privilegiado compartido — descubrir sshd y correr `sshd -T`

Extrae de `sshd_config.py` el descubrimiento de `sshd` (shell Linux, binario de confianza, root/sudo) a un módulo reutilizable, para que la prueba E lea `sshd -T` con la misma seguridad sin duplicar un camino más débil.

**Files:**
- Create: `ssh_auditor/plugins/privileged.py`
- Modify: `ssh_auditor/plugins/sshd_config.py` (usar el helper)
- Test: `tests/test_privileged.py` (nuevo)

**Interfaces:**
- Produces: `async def resolve_sshd(run, *, profile_id) -> SshdTarget | SkipReason` donde `run(command, timeout_s) -> CommandResult`; `SshdTarget` es un dataclass `(path:str, prefix:list[str], runner:str, version:str, system:str)`; `SkipReason` es un dataclass `(reason:str, extra:dict)`. También `async def effective_sshd(run, target, extra_args=()) -> CommandResult` que ejecuta `sshd -T [args]` con el prefijo correcto.

- [ ] **Step 1: Test del descubrimiento con un `run` falso**

```python
# tests/test_privileged.py
import pytest
from ssh_auditor.plugins.authentication import CommandResult
from ssh_auditor.plugins.privileged import resolve_sshd, SshdTarget, SkipReason


def _run_table(table):
    async def run(command, timeout_s=10.0):
        for needle, result in table:
            if needle in command:
                return result
        return CommandResult(stdout="", stderr="", exit_status=127)
    return run


@pytest.mark.asyncio
async def test_resolve_sshd_root_happy_path():
    run = _run_table([
        ("uname -s", CommandResult("Linux", "", 0)),
        ("command -v sshd", CommandResult("/usr/sbin/sshd\n", "", 0)),
        ("stat", CommandResult("0\t755", "", 0)),
        ("-V", CommandResult("", "OpenSSH_9.6p1", 0)),
        ("id -u", CommandResult("0", "", 0)),
    ])
    target = await resolve_sshd(run, profile_id="generic")
    assert isinstance(target, SshdTarget)
    assert target.path == "/usr/sbin/sshd"
    assert target.prefix == []
    assert target.runner == "root"


@pytest.mark.asyncio
async def test_resolve_sshd_non_linux_is_skip():
    run = _run_table([("uname -s", CommandResult("Darwin", "", 0))])
    result = await resolve_sshd(run, profile_id="generic")
    assert isinstance(result, SkipReason)
    assert "Linux" in result.reason
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_privileged.py -v`
Expected: FAIL (`No module named 'ssh_auditor.plugins.privileged'`).

- [ ] **Step 3: Crear `privileged.py` moviendo la lógica de descubrimiento**

Mover a `ssh_auditor/plugins/privileged.py` la secuencia que hoy vive en `sshd_config.py._collect_connected` desde `uname -s` hasta la verificación de `id -u`/`sudo -n` (las líneas que resuelven `system`, `path`, `trusted_binary`, `version`, `root`, `prefix`, `runner`). Envolverla en `resolve_sshd(run, *, profile_id)`, devolviendo `SkipReason(reason, extra)` en cada caso de salida temprana y `SshdTarget(...)` al final. Reusar los helpers `_command`, `_safe_text`, `parse_sshd_output` importándolos o moviéndolos según convenga (mantener `parse_sshd_output` donde está e importarlo). Añadir:

```python
from dataclasses import dataclass, field

@dataclass
class SshdTarget:
    path: str
    prefix: list[str]
    runner: str
    version: str
    system: str

@dataclass
class SkipReason:
    reason: str
    extra: dict = field(default_factory=dict)

async def effective_sshd(run, target: "SshdTarget", extra_args=()):
    from ssh_auditor.plugins.sshd_config import _command  # argv quoting helper
    argv = [*target.prefix, target.path, "-T", *extra_args]
    return await run(_command(argv), 15.0)
```

- [ ] **Step 4: Rewire `sshd_config._collect_connected` para usar el helper**

Reemplazar el bloque de descubrimiento en `sshd_config.py` por:

```python
        from ssh_auditor.plugins.privileged import resolve_sshd, SkipReason
        async def run(command, timeout_s=10.0):
            return await self._run(connection, command, timeout_s)
        target = await resolve_sshd(run, profile_id=profile.id)
        if isinstance(target, SkipReason):
            return _skip(target.reason, profile=profile.id, **target.extra)
        path, prefix, runner, version, system = (
            target.path, target.prefix, target.runner, target.version, target.system)
```

Dejar el resto de `_collect_connected` (policy, `sshd -T`, contexts, files) igual.

- [ ] **Step 5: Correr los tests de sshd_config + el nuevo**

Run: `pytest tests/test_privileged.py tests/test_sshd_config.py -v`
Expected: PASS (las pruebas de `sshd_config`, que ya existían, actúan de red de seguridad del refactor).

- [ ] **Step 6: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 5: Plugin E — memoria yescrypt

**Files:**
- Create: `ssh_auditor/plugins/memory.py`
- Modify: `ssh_auditor/plugins/__init__.py` (import para registrar)
- Test: `tests/test_memory.py` (nuevo)

**Interfaces:**
- Produces: `MemoryYescryptPlugin` con `meta.id="memory_yescrypt"`, `category="E"`, `impact="low"`, `requires_auth=True`, `privilege="root-or-sudo"`, `timeout_s=60.0`.
- Consumes: `resolve_sshd`/`effective_sshd` (Tarea 4), `open_authenticated_connection`/`run_command_on_connection`/`CommandResult` (authentication.py), `ctx.policy["performance"]` (Tarea 2).

- [ ] **Step 1: Test del `evaluate` (matemática de slots, grados)**

```python
# tests/test_memory.py
import pytest
from ssh_auditor.models import Evidence, Status
from ssh_auditor.plugins.memory import MemoryYescryptPlugin

PERF = {"hash_cost_mib": 16, "expected_method": "yescrypt",
        "login_latency_limit_ms": 1500, "mem_warn_fraction": 0.75,
        "concurrency_success_floor_pct": 95}


def _ev(**over):
    data = {"applicable": True, "mem_available_mib": 1531,
            "maxstartups": {"start": 10, "rate": 30, "full": 100},
            "configured_method": "yescrypt", "login_ms": 410, "errors": {}}
    data.update(over)
    return Evidence(data=data)


def _by_id(findings):
    return {f.id: f for f in findings}


def test_worst_case_over_available_is_fail():
    # 100 * 16 = 1600 MiB > 1531 available
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.FAIL


def test_comfortable_margin_is_pass():
    # full=40 -> 640 MiB, well under 0.75*1531
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups={"start": 10, "rate": 30, "full": 40}), {"performance": PERF}))
    assert f["pre-auth-memory"].status == Status.PASS


def test_latency_over_limit_is_warn_or_fail():
    f = _by_id(MemoryYescryptPlugin().evaluate(_ev(login_ms=4000), {"performance": PERF}))
    assert f["login-latency"].status in (Status.WARN, Status.FAIL)


def test_wrong_method_is_warn():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(configured_method="sha512"), {"performance": PERF}))
    assert f["hash-method"].status == Status.WARN


def test_missing_maxstartups_does_not_crash_or_error():
    f = _by_id(MemoryYescryptPlugin().evaluate(
        _ev(maxstartups=None, errors={"maxstartups": "sshd -T unavailable"}),
        {"performance": PERF}))
    assert "pre-auth-memory" not in f or f["pre-auth-memory"].status != Status.ERROR
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_memory.py -v`
Expected: FAIL (`No module named 'ssh_auditor.plugins.memory'`).

- [ ] **Step 3: Implementar el plugin**

```python
# ssh_auditor/plugins/memory.py
from __future__ import annotations

import re
import time

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import (
    CommandResult, open_authenticated_connection, run_command_on_connection,
)
from ssh_auditor.plugins.base import Context, Meta, register
from ssh_auditor.plugins.privileged import effective_sshd, resolve_sshd, SkipReason


def _skip(reason: str) -> Evidence:
    return Evidence(data={"applicable": False, "skip_reason": reason})


def _parse_maxstartups(text: str):
    # From `sshd -T`: "maxstartups 10:30:100" (or a single number).
    for line in text.splitlines():
        if line.startswith("maxstartups"):
            spec = line.split(None, 1)[1].strip() if " " in line else ""
            parts = spec.split(":")
            nums = [int(p) for p in parts if p.isdigit()]
            if len(nums) == 1:
                return {"start": nums[0], "rate": 0, "full": nums[0]}
            if len(nums) == 3:
                return {"start": nums[0], "rate": nums[1], "full": nums[2]}
    return None


def _grep_one(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.startswith(key):
            return line[len(key):].strip()
    return ""


class MemoryYescryptPlugin:
    meta = Meta(
        id="memory_yescrypt", version="1", category="E",
        name="Pre-auth memory (yescrypt)", impact="low",
        requires_auth=True, timeout_s=60.0, privilege="root-or-sudo",
        actions=("Read /proc/meminfo and sshd -T (read-only)",
                 "Time one password login", "Read the configured hash method"),
    )

    async def collect(self, ctx: Context) -> Evidence:
        profile = ctx.profile
        if profile is None:
            return _skip("The device profile was not provided to the plugin.")
        method = getattr(ctx.credentials, "method", AuthMethod.NONE)
        if method in (None, "", "none", AuthMethod.NONE):
            return _skip("Authenticated credentials are required for the memory check.")

        errors: dict[str, str] = {}
        data: dict = {"applicable": True, "errors": errors,
                      "mem_available_mib": None, "maxstartups": None,
                      "logingracetime_s": None, "persourcepenalties": None,
                      "configured_method": "unknown", "login_ms": None}

        t0 = time.monotonic()
        try:
            async with open_authenticated_connection(ctx) as connection:
                data["login_ms"] = int((time.monotonic() - t0) * 1000)

                async def run(command, timeout_s=10.0):
                    return await run_command_on_connection(
                        connection, command, timeout_s=timeout_s, max_output_bytes=65536)

                meminfo = await run("grep -E 'MemTotal|MemFree|MemAvailable' /proc/meminfo", 5.0)
                match = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo.stdout)
                if match:
                    data["mem_available_mib"] = int(match.group(1)) // 1024
                else:
                    errors["mem_available"] = "MemAvailable not found in /proc/meminfo"

                method_cmd = await run(
                    "grep -i '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null; "
                    "grep -i yescrypt /etc/pam.d/common-password /etc/pam.d/system-auth "
                    "2>/dev/null", 5.0)
                blob = method_cmd.stdout.lower()
                if "yescrypt" in blob:
                    data["configured_method"] = "yescrypt"
                elif "sha512" in blob:
                    data["configured_method"] = "sha512"

                target = await resolve_sshd(run, profile_id=profile.id)
                if isinstance(target, SkipReason):
                    errors["maxstartups"] = f"sshd -T unavailable: {target.reason}"
                else:
                    eff = await effective_sshd(run, target)
                    if eff.exit_status == 0 and not eff.truncated:
                        data["maxstartups"] = _parse_maxstartups(eff.stdout)
                        grace = _grep_one(eff.stdout, "logingracetime")
                        data["logingracetime_s"] = int(grace) if grace.isdigit() else None
                        data["persourcepenalties"] = _grep_one(eff.stdout, "persourcepenalties") or None
                    else:
                        errors["maxstartups"] = "sshd -T failed"
        except Exception as exc:  # noqa: BLE001 - never surface credential-bearing text
            if data["login_ms"] is None:
                return _skip(f"Could not open the authenticated session: {type(exc).__name__}")
            errors["collect"] = type(exc).__name__
        return Evidence(data=data)

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if not data.get("applicable"):
            return [Finding(id="memory-applicability", status=Status.SKIP,
                            summary=data.get("skip_reason", "Not applicable."),
                            source="host")]
        perf = (policy or {}).get("performance", {})
        cost = perf.get("hash_cost_mib", 16)
        findings: list[Finding] = []

        avail = data.get("mem_available_mib")
        ms = data.get("maxstartups")
        if avail is not None and ms is not None:
            worst = ms["full"] * cost
            slots = avail // cost
            warn_fraction = perf.get("mem_warn_fraction", 0.75)
            if worst > avail:
                status, summary = Status.FAIL, (
                    f"Pre-auth worst case {worst} MiB exceeds MemAvailable {avail} MiB "
                    f"(MaxStartups full={ms['full']} × {cost} MiB).")
                rec = "Lower the third MaxStartups value, add swap, or set PerSourcePenalties."
            elif worst > avail * warn_fraction:
                status, summary, rec = Status.WARN, (
                    f"Pre-auth worst case {worst} MiB leaves little margin over "
                    f"MemAvailable {avail} MiB."), "Consider lowering MaxStartups."
            else:
                status, summary, rec = Status.PASS, (
                    f"Pre-auth worst case {worst} MiB fits within MemAvailable "
                    f"{avail} MiB."), ""
            findings.append(Finding(id="pre-auth-memory", status=status,
                                    summary=summary, recommendation=rec, source="host"))
            findings.append(Finding(
                id="memory-slots", status=Status.INFO,
                summary=f"~{slots} concurrent yescrypt hashes fit in MemAvailable "
                        f"({avail} MiB / {cost} MiB); quarter≈{(avail // 4) // cost}, "
                        f"third≈{(avail // 3) // cost}.", source="host"))
        elif data.get("errors", {}).get("maxstartups"):
            findings.append(Finding(
                id="memory-maxstartups", status=Status.INFO,
                summary=f"Could not read MaxStartups: {data['errors']['maxstartups']}.",
                source="host"))

        login_ms = data.get("login_ms")
        limit = perf.get("login_latency_limit_ms", 1500)
        if login_ms is not None:
            if login_ms > limit:
                st = Status.FAIL if login_ms > limit * 2 else Status.WARN
                findings.append(Finding(
                    id="login-latency", status=st,
                    summary=f"Password login took {login_ms} ms (limit {limit} ms).",
                    recommendation="Review the yescrypt cost (count) for this platform.",
                    source="host"))
            else:
                findings.append(Finding(
                    id="login-latency", status=Status.PASS,
                    summary=f"Password login took {login_ms} ms (within {limit} ms).",
                    source="host"))

        expected = perf.get("expected_method", "yescrypt")
        observed = data.get("configured_method", "unknown")
        if observed == "unknown":
            findings.append(Finding(id="hash-method", status=Status.INFO,
                summary="Could not determine the configured password hash method.",
                source="host"))
        elif observed == expected:
            findings.append(Finding(id="hash-method", status=Status.PASS,
                summary=f"Configured password hash method is {observed}.", source="host"))
        else:
            findings.append(Finding(id="hash-method", status=Status.WARN,
                summary=f"Configured hash method is {observed}, expected {expected}.",
                recommendation=f"Switch password hashing to {expected}.", source="host"))

        return findings or [Finding(id="memory", status=Status.SKIP,
                                    summary="No memory data collected.", source="host")]


register(MemoryYescryptPlugin())
```

- [ ] **Step 4: Registrar el plugin**

En `ssh_auditor/plugins/__init__.py`, añadir `memory` a la lista de imports:

```python
from . import (  # noqa: F401  (plugins register themselves on import)
    authentication, connectivity, memory, negotiation, sshd_config,
)
```

- [ ] **Step 5: Correr y ver pasar**

Run: `pytest tests/test_memory.py -v`
Expected: PASS.

- [ ] **Step 6: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 6: Plugin F — concurrencia acotada

**Files:**
- Create: `ssh_auditor/plugins/concurrency.py`
- Modify: `ssh_auditor/plugins/__init__.py`
- Test: `tests/test_concurrency.py` (nuevo)

**Interfaces:**
- Produces: `ConcurrencyBoundedPlugin` con `meta.id="concurrency_bounded"`, `category="F"`, `impact="medium"`, `requires_auth=True`, `timeout_s=330.0`.
- Consumes: `open_authenticated_connection`/`run_command_on_connection`/`_safe_command`/`_context_credentials` (authentication.py), `ctx.params["load"]`, `ctx.connection_limit`, `ctx.policy["performance"]`.

- [ ] **Step 1: Test de parada automática con un login falso**

```python
# tests/test_concurrency.py
import asyncio
import pytest
from ssh_auditor.models import AuthMethod, Credentials, Evidence, Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins import concurrency as conc


def _ctx(monkeypatch, latencies, *, limit=4, iterations=50, p95_factor=3, error_rate_pct=10):
    calls = {"n": 0}

    async def fake_cycle(ctx):
        i = calls["n"]
        calls["n"] += 1
        outcome = latencies[i] if i < len(latencies) else latencies[-1]
        if isinstance(outcome, Exception):
            raise outcome
        await asyncio.sleep(0)
        return outcome  # ms

    monkeypatch.setattr(conc, "_one_login_cycle", fake_cycle)
    ctx = Context(host="h", port=22,
                  policy={"performance": {"concurrency_success_floor_pct": 95}},
                  params={"load": {"iterations": iterations,
                                   "error_rate_pct": error_rate_pct,
                                   "p95_factor": p95_factor}},
                  emit=lambda _m: None,
                  credentials=Credentials(method=AuthMethod.PASSWORD, username="u",
                                          password="p"),
                  connection_limit=limit)
    return ctx, calls


@pytest.mark.asyncio
async def test_stops_when_error_rate_exceeded(monkeypatch):
    # Baseline (i=0) succeeds; every burst cycle raises -> error rate 100% > 10%.
    ctx, calls = _ctx(monkeypatch, [100, RuntimeError("x")], iterations=50)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["stopped_early"] is True
    assert "error rate" in ev.data["stop_reason"]
    assert calls["n"] < 50  # did not run all 50 bursts


@pytest.mark.asyncio
async def test_p95_only_trips_after_warmup(monkeypatch):
    # Baseline 100ms; first burst sample is huge but must not trip before 10 cycles.
    latencies = [100, 10000] + [100] * 60
    ctx, _ = _ctx(monkeypatch, latencies, iterations=15, p95_factor=3)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["completed"] >= 10  # warmup protected the early slow sample


@pytest.mark.asyncio
async def test_clean_run_reports_latencies(monkeypatch):
    ctx, _ = _ctx(monkeypatch, [100] * 60, iterations=20)
    ev = await conc.ConcurrencyBoundedPlugin().collect(ctx)
    assert ev.data["succeeded"] == 20
    assert ev.data["stopped_early"] is False
    assert ev.data["latency_ms"]["p95"] >= ev.data["latency_ms"]["median"]


def test_evaluate_fail_on_blocked():
    ev = Evidence(data={"applicable": True, "succeeded": 3, "completed": 5,
                        "failed": 2, "stopped_early": True, "stop_reason": "blocked: lockout",
                        "latency_ms": {"min": 1, "median": 2, "p95": 3, "max": 4},
                        "auth_method": "password", "base_login_ms": 100})
    findings = conc.ConcurrencyBoundedPlugin().evaluate(ev, {"performance": {}})
    assert any(f.status == Status.FAIL for f in findings)
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_concurrency.py -v`
Expected: FAIL (`No module named 'ssh_auditor.plugins.concurrency'`).

- [ ] **Step 3: Implementar el plugin**

```python
# ssh_auditor/plugins/concurrency.py
from __future__ import annotations

import asyncio
import time

import asyncssh

from ssh_auditor.models import AuthMethod, Evidence, Finding, Status
from ssh_auditor.plugins.authentication import (
    _context_credentials, _safe_command, open_authenticated_connection,
    run_command_on_connection,
)
from ssh_auditor.plugins.base import Context, Meta, register

WARMUP_CYCLES = 10
_BLOCK_SIGNALS = ("too many authentication", "too many sessions", "connection refused",
                  "connection reset", "max startups")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round((pct / 100) * (len(ordered) - 1))))
    return ordered[k]


async def _one_login_cycle(ctx: Context) -> float:
    """Open one authenticated connection, run the harmless command, close it.
    Return the elapsed milliseconds. Raises on failure (caught by the caller)."""
    command = _safe_command(ctx)
    start = time.monotonic()
    async with open_authenticated_connection(ctx) as connection:
        await run_command_on_connection(connection, command, timeout_s=10.0)
    return (time.monotonic() - start) * 1000


def _is_block_signal(exc: Exception) -> bool:
    if isinstance(exc, asyncssh.PermissionDenied):
        return True  # lockout / rejected credential during the burst
    text = str(exc).lower()
    return any(sig in text for sig in _BLOCK_SIGNALS)


class ConcurrencyBoundedPlugin:
    meta = Meta(
        id="concurrency_bounded", version="1", category="F",
        name="Bounded concurrency", impact="medium",
        requires_auth=True, timeout_s=330.0, privilege="normal",
        actions=("Measure one baseline login",
                 "Run bounded concurrent login/command/logout cycles",
                 "Stop automatically on errors, latency, or a block signal"),
    )

    async def collect(self, ctx: Context) -> Evidence:
        credentials = _context_credentials(ctx)
        if credentials.method == AuthMethod.NONE:
            return Evidence(data={"applicable": False,
                                  "skip_reason": "Choose an authentication method for this test."})

        load = (ctx.params or {}).get("load", {})
        iterations = int(load.get("iterations") or 1)
        error_rate_pct = float(load.get("error_rate_pct", 10))
        p95_factor = float(load.get("p95_factor", 3))
        concurrency = max(1, int(ctx.connection_limit))

        # Baseline login (also verifies the credential before the burst).
        try:
            base_ms = await _one_login_cycle(ctx)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, asyncssh.PermissionDenied):
                return Evidence(data={"applicable": True, "base_login_ms": None,
                                      "completed": 0, "succeeded": 0, "failed": 0,
                                      "stopped_early": True, "stop_reason": "rejected",
                                      "auth_method": credentials.method.value,
                                      "latency_ms": {}})
            return Evidence(data={"applicable": False,
                                  "skip_reason": f"Baseline login failed: {type(exc).__name__}"})

        latencies: list[float] = []
        completed = succeeded = failed = 0
        stop_reason = ""
        sem = asyncio.Semaphore(concurrency)
        emit = ctx.emit
        stop = asyncio.Event()

        async def one(i: int):
            nonlocal completed, succeeded, failed, stop_reason
            if stop.is_set():
                return
            async with sem:
                if stop.is_set():
                    return
                try:
                    ms = await _one_login_cycle(ctx)
                    latencies.append(ms)
                    succeeded += 1
                except Exception as exc:  # noqa: BLE001 - classify without leaking text
                    failed += 1
                    if _is_block_signal(exc):
                        stop_reason = "blocked: a block/lockout signal was received"
                        stop.set()
                finally:
                    completed += 1
                # Auto-stop checks after each completed cycle.
                if not stop.is_set():
                    if completed and (failed / completed) * 100 > error_rate_pct:
                        stop_reason = f"error rate exceeded {error_rate_pct:g}%"
                        stop.set()
                    elif completed >= WARMUP_CYCLES and latencies:
                        if _percentile(latencies, 95) > p95_factor * base_ms:
                            stop_reason = f"p95 latency exceeded {p95_factor:g}× the baseline"
                            stop.set()
                emit(f"cycle {completed}/{iterations} ok={succeeded} fail={failed}")

        # Launch in bounded waves so a stop signal halts promptly.
        pending = [asyncio.create_task(one(i)) for i in range(iterations)]
        await asyncio.gather(*pending)

        latency_ms = {}
        if latencies:
            latency_ms = {
                "min": int(min(latencies)), "median": int(_percentile(latencies, 50)),
                "p95": int(_percentile(latencies, 95)), "max": int(max(latencies)),
            }
        return Evidence(data={
            "applicable": True, "auth_method": credentials.method.value,
            "base_login_ms": int(base_ms),
            "requested": {"concurrency": concurrency, "iterations": iterations,
                          "error_rate_pct": error_rate_pct, "p95_factor": p95_factor},
            "completed": completed, "succeeded": succeeded, "failed": failed,
            "latency_ms": latency_ms,
            "stopped_early": bool(stop_reason), "stop_reason": stop_reason,
        })

    def evaluate(self, evidence: Evidence, policy: dict) -> list[Finding]:
        data = evidence.data
        if not data.get("applicable"):
            return [Finding(id="concurrency-applicability", status=Status.SKIP,
                            summary=data.get("skip_reason", "Not applicable."),
                            source="host")]
        perf = (policy or {}).get("performance", {})
        floor = perf.get("concurrency_success_floor_pct", 95)
        completed = data.get("completed", 0)
        succeeded = data.get("succeeded", 0)
        reason = data.get("stop_reason", "")
        success_pct = (succeeded / completed * 100) if completed else 0

        if reason.startswith("blocked") or reason == "rejected":
            status = Status.FAIL
        elif reason.startswith("error rate"):
            status = Status.FAIL
        elif success_pct < floor:
            status = Status.FAIL
        elif reason.startswith("p95"):
            status = Status.WARN
        elif success_pct < 100:
            status = Status.WARN
        else:
            status = Status.PASS

        lat = data.get("latency_ms", {})
        lat_text = (f"min {lat['min']} / median {lat['median']} / p95 {lat['p95']} / "
                    f"max {lat['max']} ms") if lat else "no successful cycles"
        summary = (f"{succeeded}/{completed} successful ({success_pct:.0f}%) over "
                   f"{data.get('auth_method')}; latency {lat_text}.")
        if reason:
            summary += f" Stopped early: {reason}."
        rec = ("Reduce concurrency/iterations or investigate the device limits."
               if status == Status.FAIL else "")
        return [Finding(id="concurrency_bounded", status=status, summary=summary,
                        recommendation=rec, source="host")]


register(ConcurrencyBoundedPlugin())
```

- [ ] **Step 4: Registrar el plugin**

En `ssh_auditor/plugins/__init__.py`:

```python
from . import (  # noqa: F401  (plugins register themselves on import)
    authentication, concurrency, connectivity, memory, negotiation, sshd_config,
)
```

- [ ] **Step 5: Correr y ver pasar**

Run: `pytest tests/test_concurrency.py -v`
Expected: PASS.

- [ ] **Step 6: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 7: MCP — pasar `load` y exponer las pruebas nuevas

**Files:**
- Modify: `ssh_auditor/mcp/server.py` (`start_scan` acepta `load`)
- Test: `tests/test_mcp_load.py` (nuevo)

**Interfaces:**
- Consumes: `start_scan(..., load: dict | None = None)` que arma `ScanRequest(params={"load": load or {}}, ...)`. Las pruebas `memory_yescrypt` y `concurrency_bounded` ya aparecen en `list_tests` por estar registradas (no requiere cambio).

- [ ] **Step 1: Test de que start_scan reenvía load**

```python
# tests/test_mcp_load.py
import pytest
from ssh_auditor.models import ScanRequest


def test_scanrequest_carries_load_params():
    req = ScanRequest(target_host="10.0.0.5", tests=["concurrency_bounded"],
                      confirm_impact=True, params={"load": {"iterations": 5}})
    assert req.params["load"]["iterations"] == 5
```

- [ ] **Step 2: Correr y ver pasar/fallar**

Run: `pytest tests/test_mcp_load.py -v`
Expected: PASS (el modelo ya acepta `params`; este test fija el contrato).

- [ ] **Step 3: Añadir `load` al wrapper MCP**

En `ssh_auditor/mcp/server.py`, en la firma de `start_scan` añadir `load: dict | None = None` y, al construir el `ScanRequest`, incluir `params={"load": load or {}}`. Documentar en el docstring: `load: {iterations?, error_rate_pct?, p95_factor?} para la prueba concurrency_bounded; concurrency controla el máximo en vuelo (≤ límite del perfil).`

- [ ] **Step 4: Suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 8: Web — módulo compartido + página "Load testing"

**Files:**
- Create: `ssh_auditor/web/static/core.js` (módulo compartido extraído de `app.js`)
- Create: `ssh_auditor/web/static/load.html`
- Create: `ssh_auditor/web/static/load.js`
- Modify: `ssh_auditor/web/static/app.js` (importar lo común desde `core.js`)
- Modify: `ssh_auditor/web/static/index.html` (enlace en el nav a `/load.html`)
- Modify: `ssh_auditor/web/app.py` si hiciera falta servir `load.html` (revisar: hoy sirve `static/` como estáticos; si `/load.html` ya se sirve por el montaje estático, no tocar)
- Test: `tests/test_static.py` (añadir casos)

**Interfaces:**
- Produces: `core.js` exporta (como funciones globales o `window.sshCore`) `streamScan`, `readSSE`, `renderResults`, `renderCompare`, `exportScan`, y el almacén de credenciales (`savedCredential`, `credentialFromForm`, etc.). `app.js` y `load.js` consumen de ahí.

> Extracción mecánica: mover desde `app.js` a `core.js` las funciones que hoy ya son independientes del DOM de la página de auditoría (streaming SSE, render de resultados/tabs, compare, export, helpers de credenciales y `esc`). `app.js` pasa a importar esas y conservar solo lo propio del flujo de 5 pasos. Mantener el comportamiento: los tests de `test_static.py` existentes deben seguir pasando.

- [ ] **Step 1: Añadir asserts estáticos para la página nueva**

```python
# en tests/test_static.py
def test_load_testing_page_reuses_core_module():
    base = Path("ssh_auditor/web/static")
    assert (base / "core.js").exists()
    load = (base / "load.html").read_text()
    assert "core.js" in load and "load.js" in load
    assert "Load testing" in load
    # F parameter controls and the memory test are present.
    for control in ("iterations", "errorRatePct", "p95Factor", "runLoad"):
        assert f'id="{control}"' in load
    # Both pages share the streaming/render code (no duplicated renderResults).
    app = (base / "app.js").read_text()
    assert "core.js" in app or "sshCore" in app
    # The main page links to the load testing page.
    assert "/load.html" in (base / "index.html").read_text()
```

- [ ] **Step 2: Correr y ver fallar**

Run: `pytest tests/test_static.py -v`
Expected: FAIL (`core.js`/`load.html` no existen).

- [ ] **Step 3: Extraer `core.js`**

Mover las funciones DOM-independientes de `app.js` a `core.js`, exponiéndolas en `window.sshCore = { streamScan, readSSE, renderResults, renderResultsPanel, renderCompare, exportScan, savedCredential, credentialFromForm, esc, ... }`. En `app.js`, sustituir las definiciones movidas por referencias a `window.sshCore`. Cargar `core.js` antes de `app.js` en `index.html`.

- [ ] **Step 4: Crear `load.html` + `load.js`**

`load.html`: misma estructura/estilos que `index.html` (barra lateral, tema). Secciones: objetivo (host/puerto), credenciales (reutilizando el almacén por `host:port` de `core.js`), selección de E/F, y los controles numéricos de F (`iterations`, `errorRatePct`, `p95Factor`) con sus topes indicados, más el botón `runLoad`. Progreso en vivo y resultados con `window.sshCore.renderResults`. Export/compare con los botones y endpoints existentes.

`load.js`: arma el `scanBody` con `tests` = los toggles marcados (`memory_yescrypt`, `concurrency_bounded`), `confirm_impact=true` cuando F está marcado, `concurrency` = campo de concurrencia, y `params.load = {iterations, error_rate_pct, p95_factor}`. Llama a `window.sshCore.streamScan` y pinta con `renderResults`.

En `index.html`, añadir en el nav un enlace a `/load.html` (junto al de "Connect with Claude").

- [ ] **Step 5: Correr y ver pasar**

Run: `pytest tests/test_static.py -v`
Expected: PASS.

- [ ] **Step 6: Humo manual (opcional) + suite en verde**

Run: `pytest -q`
Expected: PASS.

---

## Task 9: e2e — una corrida chica de F contra el sshd en proceso

**Files:**
- Test: `tests/test_concurrency_e2e.py` (nuevo)

**Interfaces:**
- Consumes: `run_scan` (runner), `Credentials`, `ScanRequest`. La fixture compartida `ssh_server` (conftest) NO autentica; este test levanta su propio servidor con contraseña, siguiendo el patrón `_PasswordServer`/`_password_process` de `tests/test_authentication.py`. El `profile` se pasa como un `SimpleNamespace(safe_command="id")` (igual que `_ctx` en `test_authentication.py`), porque `run_scan` recibe el profile por argumento y F necesita `safe_command`.

- [ ] **Step 1: Test e2e con servidor de contraseña propio**

```python
# tests/test_concurrency_e2e.py
from types import SimpleNamespace

import asyncssh
import pytest
import pytest_asyncio

from ssh_auditor.engine.cache import TTLCache
from ssh_auditor.engine.runner import run_scan
from ssh_auditor.models import AuthMethod, Credentials, ScanRequest


class _PasswordServer(asyncssh.SSHServer):
    def begin_auth(self, _username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "audit" and password == "server-password-marker"


def _process(process):
    if process.command == "id":
        process.stdout.write("uid=1000(audit)\n")
        process.exit(0)
    else:
        process.stderr.write("unsupported\n")
        process.exit(127)


@pytest_asyncio.fixture
async def password_server():
    server = await asyncssh.create_server(
        _PasswordServer, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        process_factory=_process,
    )
    sock = server.sockets[0].getsockname()
    yield sock[0], sock[1]
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_concurrency_bounded_runs_small(password_server):
    host, port = password_server
    req = ScanRequest(
        target_host=host, port=port, profile="generic",
        tests=["concurrency_bounded"], confirm_impact=True,
        params={"load": {"iterations": 5, "error_rate_pct": 100, "p95_factor": 100}},
        credentials=Credentials(method=AuthMethod.PASSWORD, username="audit",
                                password="server-password-marker"),
    )
    sr = await run_scan(
        req, policy={"performance": {}}, tool_version="0", limit=2,
        cache=TTLCache(60), profile=SimpleNamespace(safe_command="id"),
    )
    result = next(r for r in sr.results if r.test_id == "concurrency_bounded")
    assert result.evidence.data["completed"] >= 1
    assert result.evidence.data["succeeded"] >= 1
    assert "latency_ms" in result.evidence.data
```

- [ ] **Step 2: Correr**

Run: `pytest tests/test_concurrency_e2e.py -v`
Expected: PASS (si falla el handshake de proceso, revisar la firma de `process_factory`/`session_factory` de la versión de asyncssh en `requirements.txt`).

- [ ] **Step 3: Suite completa final**

Run: `pytest -q`
Expected: PASS (todos los módulos, incluidos los nuevos).

---

## Notas de cierre

- **Impacto de F = medium**: aparece en el grupo bloqueado del paso 3 y exige `confirm_impact`. La página "Load testing" marca `confirm_impact=true` sola cuando F está seleccionada (es una página dedicada a estas pruebas).
- **Cancelación**: `ScanJobs.cancel` ya cancela la task; `collect` de F responde a `CancelledError` porque `asyncio.gather` propaga la cancelación a los `one(i)`. No requiere código extra, pero verificar manualmente si se expone un botón de cancelar en la página.
- **count de yescrypt**: sin leer `/etc/shadow` no se verifica el parámetro exacto; E confirma el método y usa la latencia como proxy (ver spec §2.3). Confirmar con el equipo cómo aplican `count`.
