# Fase 4 — Memoria yescrypt y concurrencia acotada (diseño)

Fecha: 2026-10-09
Estado: diseño aprobado en conversación; pendiente de revisión del usuario antes del plan.

## 1. Objetivo y contexto

Implementar las pruebas **E (memoria yescrypt)** y **F (concurrencia y estabilidad)** de
`instrucciones.md` (§4.E, §4.F, §13 Fase 4), para equipos Opengear/routers de laboratorio
autorizados. El propósito operativo: saber cuántas verificaciones de contraseña yescrypt
aguanta un equipo antes de quedarse sin memoria, y cómo se comporta bajo una carga de
logins **acotada**, para comparar entre firmwares/modelos.

Ambas pruebas pasan por la tubería que ya existe (`run_scan` → cache TTL → SSE → export →
compare). No se crea tubería nueva.

### Principio rector (alcance)

`instrucciones.md` es explícita: *"Validación, no ataque. Sin fuerza bruta, password
spraying ni intentos ilimitados"*, y para yescrypt *"Es un cálculo, no una prueba de
carga"*.

**Dentro de alcance:** medir la memoria por **cálculo** (leer `/proc/meminfo` y `sshd -T`)
y correr concurrencia **con techo de perfil y parada automática**.

**Fuera de alcance (explícito):** NO se implementa el método de "inundar con ráfagas de
hashes/logins hasta encontrar el punto de bloqueo". Buscar el punto de ruptura es, por
definición, provocar el agotamiento de memoria del equipo; se descarta a favor del cálculo
y de la carga acotada que corta sola antes de causar daño.

## 2. Prueba E — Memoria yescrypt

- **id:** `memory_yescrypt` · **categoría:** `E` · **requiere auth:** sí ·
  **privilegio:** `root-or-sudo` (necesita `sshd -T`) · **impacto:** `low` (hace un solo
  login). Sin credenciales o sin método de auth → `SKIP`, igual que `sshd_config`.

### 2.1 Recolección (`collect`), todo solo-lectura, sin tocar `/etc/shadow`

1. `grep -E 'MemTotal|MemFree|MemAvailable' /proc/meminfo` → `mem_available_kib`.
2. `sshd -T` (reusando el mismo acceso privilegiado que `sshd_config`) → `maxstartups`,
   `logingracetime`, `persourcepenalties`.
3. Método de hash **configurado** (no un hash real): `ENCRYPT_METHOD` de
   `/etc/login.defs` y/o la línea de `pam_unix`/`pam_yescrypt` en la config de PAM. Con
   esto se confirma que el método es yescrypt sin leer ninguna contraseña.
4. **Un** login por contraseña cronometrado de punta a punta (`login_ms`), usando las
   credenciales del paso 2. Es el proxy empírico del costo del hash.

Forma de la evidencia (`Evidence.data`):

```
{
  "applicable": true,
  "mem_available_mib": 1531,
  "maxstartups": {"start": 10, "rate": 30, "full": 100},
  "logingracetime_s": 120,
  "persourcepenalties": "...",      # texto crudo, informativo
  "configured_method": "yescrypt",  # o "sha512", "unknown"
  "login_ms": 410,
  "errors": {}                      # por campo que no se pudo leer
}
```

### 2.2 Evaluación (`evaluate`), contra política

Constantes de política (ver §5): `hash_cost_mib` (16), `login_latency_limit_ms`,
`expected_method` ("yescrypt"), `mem_warn_fraction` (0.75).

- **Peor caso pre-auth** = `maxstartups.full × hash_cost_mib`. Esta es la cifra que §4.E
  nombra ("3er valor de MaxStartups × 16 MiB ≈ 1,6 GiB con MaxStartups=100").
  - `FAIL` si `peor_caso > mem_available_mib` → el equipo puede quedarse sin memoria
    (OOM) **antes** de autenticar. Recomendación: bajar el 3er valor de `MaxStartups`,
    añadir swap, o `PerSourcePenalties`.
  - `WARN` si `peor_caso > mem_available_mib × mem_warn_fraction` → poco margen.
  - `PASS` en otro caso.
- **Slots disponibles** = `floor(mem_available_mib / hash_cost_mib)` → `INFO` (cifra de
  cabecera; con 1531 MiB y 16 MiB ≈ 95 slots teóricos; el verdadero cuello es el peor
  caso de MaxStartups de arriba). Se incluyen como INFO las estimaciones a 1/4 y 1/3 de
  `MemAvailable` (las heurísticas que usa el equipo del proyecto), para comparar.
- **Latencia:** `login_ms` vs `login_latency_limit_ms` → `PASS`/`WARN`/`FAIL`.
- **Método:** `configured_method == expected_method` → `PASS`; distinto → `WARN`;
  `unknown` → `INFO` ("método no determinado desde la configuración").

### 2.3 Limitación documentada (count)

El parámetro `count` de yescrypt solo vive dentro del hash en `/etc/shadow`. Como por
decisión del usuario E **no** lee `/etc/shadow`, `count` no se verifica directamente: se
toma el esperado de la política y la **latencia medida** actúa como comprobación empírica
(un login dentro del límite implica que el costo configurado es aceptable). Queda como
pregunta para el equipo cómo aplican `count` (ver §8). Si en el futuro se quisiera
verificar el prefijo `$y$j9T$` leyendo solo la cabecera del hash con root, sería un toggle
aparte, fuera de este diseño.

## 3. Prueba F — Concurrencia acotada

- **id:** `concurrency_bounded` · **categoría:** `F` · **requiere auth:** sí ·
  **impacto:** `medium` (siempre exige `confirm_impact`; cae en el grupo bloqueado del
  paso 3). Sin credenciales → `SKIP`.

### 3.1 Parámetros por corrida

Viajan en `ScanRequest.params["load"]` (validados en el servidor), salvo la concurrencia
que reusa el campo existente `ScanRequest.concurrency`:

| Parámetro | Default | Tope | Nota |
|---|---:|---|---|
| `concurrency` (máx. en vuelo) | `profile.max_concurrency` | `profile.max_concurrency` | el servidor ya rechaza por encima |
| `iterations` | `min(50, max_connections)` | `profile.max_connections` | nº total de ciclos login→cmd→logout |
| `error_rate_pct` | 10 | 100 | umbral de parada por errores |
| `p95_factor` | 3 | — | parada si p95 > factor × login base |
| `auth_method` | el del paso 2 | — | método a ejercitar |

El `generic` trae `max_connections: 20`, así que ahí el default efectivo de `iterations`
es 20; un perfil pensado para carga debe subir `max_connections`. La parada por **p95**
solo se evalúa tras un calentamiento mínimo (≥ 10 ciclos completos), para no cortar por
la primera muestra lenta; las paradas por error y por señal de bloqueo aplican desde el
primer ciclo.

### 3.2 Ejecución (`collect`)

1. **Login base**: un login secuencial para medir la latencia de referencia
   (`base_login_ms`). También sirve de verificación de credenciales antes de la ráfaga.
2. **Ráfaga acotada**: `iterations` ciclos de [conectar → autenticar → comando inocuo del
   perfil → cerrar], con hasta `concurrency` en vuelo mediante el semáforo por host que ya
   existe (`engine/limits.py` `_LIMITS`), de modo que varios ingenieros contra el mismo
   equipo comparten el tope.
3. **Parada automática**, revisada tras cada ciclo terminado:
   - tasa de error > `error_rate_pct`, o
   - p95 de latencia > `p95_factor × base_login_ms`, o
   - **señal de bloqueo** (conexión rechazada, lockout de la cuenta, "too many sessions"
     / `MaxStartups` agotado) → corta **de inmediato**.
   Al cortar se registra `stopped_early` y el motivo.
4. **Cancelación**: respeta `asyncio.CancelledError`; el job ya soporta `cancel()`
   (`engine/jobs.py`), así que la UI/MCP pueden abortar la corrida.

Forma de la evidencia:

```
{
  "applicable": true,
  "auth_method": "password",
  "base_login_ms": 410,
  "requested": {"concurrency": 4, "iterations": 50, "error_rate_pct": 10, "p95_factor": 3},
  "completed": 50, "succeeded": 50, "failed": 0,
  "latency_ms": {"min": 390, "median": 430, "p95": 520, "max": 610},
  "stopped_early": false, "stop_reason": ""
}
```

### 3.3 Evaluación

Constante de política: `concurrency_success_floor_pct` (ver §5).

- `PASS` si terminó las iteraciones dentro de los umbrales y el éxito ≥ piso.
- `WARN` si cortó por latencia (p95), o éxito entre el piso y el 100%.
- `FAIL` si cortó por errores o por señal de bloqueo, o el éxito quedó bajo el piso.
- Hallazgo `INFO` con el resumen de latencias y % de éxito, separado por método de auth.

## 4. Backend

- **Plugins nuevos**: `ssh_auditor/plugins/memory.py` (`MemoryYescryptPlugin`) y
  `ssh_auditor/plugins/concurrency.py` (`ConcurrencyBoundedPlugin`), registrados en
  `ssh_auditor/plugins/__init__.py` como el resto. Reusan `run_authenticated_command` y
  el patrón collect/evaluate.
- **Parámetros**: un sub-modelo tipado opcional `LoadParams` se valida desde
  `ScanRequest.params["load"]` en la capa de servicio (`service.py`), aplicando los topes
  del perfil. `concurrency` sigue en su campo actual.
- **Catálogo**: ambos plugins exponen su `Meta` (categoría, impacto, `requires_auth`,
  `privilege`, `actions`) y aparecen en `/api/v1/tests` sin cambios de contrato.

## 5. Política y perfil (configurable, §14)

Valores nuevos de **política** (todos con default; `config/policies/base.yaml` y el schema
`Policy` en `store.py`):

| Clave | Default | Uso |
|---|---:|---|
| `hash_cost_mib` | 16 | costo por verificación yescrypt (count 5) |
| `expected_method` | `yescrypt` | método de hash esperado |
| `login_latency_limit_ms` | 1500 | límite de latencia de login (E) |
| `mem_warn_fraction` | 0.75 | margen para WARN en el peor caso pre-auth |
| `concurrency_success_floor_pct` | 95 | piso de éxito para PASS en F |

El **perfil** ya aporta `max_concurrency` y `max_connections`; no cambia su schema.

## 6. Página "Load testing"

- Ruta/página nueva servida junto a `index.html` (`load.html` + entrada en el nav de la
  barra lateral). Es la superficie separada que pidió el usuario.
- **Sin duplicar lógica**: se extrae de `app.js` un módulo compartido
  (`static/core.js`) con lo común — almacén de credenciales por `host:port`, `streamScan`
  / lectura SSE, `renderResults`, `renderCompare`/export. `index.html` y `load.html`
  importan ese módulo; cada página solo aporta su formulario.
- El formulario de `load.html`: objetivo + credenciales (mismo almacén que la auditoría),
  toggles de E y F, y los campos numéricos de F con sus topes visibles. Progreso en vivo
  por SSE y resultados con el render de siempre; export y compare por los endpoints
  existentes.

## 7. Pruebas (TDD)

- **E (unidad):** `evaluate` con evidencia sintética — peor caso FAIL/WARN/PASS, slots,
  grado de latencia, método; `collect` que no invoca lectura de `/etc/shadow`.
- **F (unidad):** `collect` con un SSH falso (monkeypatch de `run_authenticated_command`)
  que devuelve latencias/errores controlados, afirmando que la parada automática dispara
  por cada umbral (errores, p95, bloqueo) y que nunca excede `concurrency`.
- **Servicio:** rechazo de `concurrency` sobre el perfil (ya existe) y validación de
  `LoadParams` (iterations ≤ max_connections, rangos de umbrales).
- **Estático:** `test_static.py` para `load.html` (nav, módulo compartido, campos).
- **e2e chico:** una corrida de F con números pequeños contra el `sshd` asyncssh en
  proceso que ya usan los tests, verificando resumen de latencias y cierre limpio.

## 8. Preguntas abiertas / a confirmar con el equipo

- **Cómo aplican `count` yescrypt** en los equipos (pam_unix `rounds=` vs. generación del
  hash). No bloquea este diseño: E detecta el método desde la config y usa la latencia
  como comprobación empírica; `count` exacto no se verifica sin leer el hash (ver §2.3).
- Confirmar que `sshd -T` está disponible y que la cuenta tiene root/sudo en los equipos
  objetivo (mismo supuesto que `sshd_config`).

## 9. Invariantes de seguridad

- F nunca abre más de `profile.max_concurrency` en vuelo; el servidor rechaza peticiones
  por encima, vengan de la web o de MCP.
- La parada por señal de bloqueo corta de inmediato, antes de seguir cargando el equipo.
- El tope por host se comparte entre ingenieros (semáforo `_LIMITS`).
- E no lee `/etc/shadow`, no genera hashes y no cambia contraseñas.
- Ninguna credencial entra en evidencia, cache, eventos ni export (redacción ya existente).

## 10. Criterios de aceptación (§13 Fase 4)

- [ ] Valida que el método configurado es yescrypt **sin sacar el hash** del equipo.
- [ ] Calcula el riesgo de DoS de memoria antes de autenticar (peor caso vs `MemAvailable`).
- [ ] Cronometra un login real como benchmark, **sin cambiar contraseñas**.
- [ ] Ejecuta concurrencia con límites de perfil, parada automática y cancelación.
- [ ] Permite comparar latencias/postura entre dos firmwares con el compare existente.
