# Plan de desarrollo — SSH Security Auditor

> Versión 2. Alcance limitado a SSH, sin estado en servidor y con acceso desde la web y desde Claude (MCP). La versión anterior está en `instrucciones-v1.md`.

## 1. Objetivo

Crear una herramienta web interna para que los ingenieros validen de forma controlada la seguridad y el comportamiento SSH de equipos Opengear, routers y otros dispositivos de red.

Los equipos se flashean con frecuencia. El foco está en obtener resultados reproducibles y **comparables entre ejecuciones**: entre versiones de firmware, entre modelos o contra una exportación de referencia.

La herramienta solo estará disponible en la red interna y la usarán varios ingenieros a la vez (unos 10, no todos al mismo tiempo).

La herramienta deberá permitir:

- Indicar el objetivo y elegir exactamente qué pruebas ejecutar.
- Autenticarse por contraseña, llave privada, certificado SSH o `keyboard-interactive`.
- Ejecutar verificaciones de negociación y configuración, pruebas funcionales de autenticación, auditoría de yescrypt y pruebas de concurrencia controladas.
- Presentar resultados claros con evidencia, explicación y acción recomendada.
- Exportar los resultados y comparar dos ejecuciones importando sus exportaciones.
- Usarse desde el navegador o desde Claude mediante un servidor MCP.

Queda fuera de esta versión:

- TLS y cualquier revisión de servicios web. Será otra herramienta.
- Base de datos e historial en servidor. Los resultados viven en el navegador y en los archivos exportados.
- Runners distribuidos. Las pruebas salen siempre desde el servidor donde corre la herramienta.
- Portal central, SSO y RBAC. La herramienta se diseñará para integrarse después en un portal que todavía no existe.
- Acceso desde internet. Solo red interna, sin token.

## 2. Principios

- **Sin estado en disco.** El servidor no guarda resultados. Solo mantiene en RAM una caché corta de ejecuciones recientes (ver §7).
- **Un motor, dos entradas.** La web y el MCP llaman al mismo motor. Ninguna lógica de pruebas vive en la interfaz.
- **Recolectar y evaluar por separado.** Cada prueba produce evidencia y la política se aplica después con una función pura. Así una exportación antigua puede reevaluarse con una política nueva sin volver a escanear.
- **Lo observado desde la red no es lo leído dentro del equipo.** El reporte los separa siempre y nunca asume que el banner representa la configuración real.
- **Validación, no ataque.** Sin fuerza bruta, password spraying ni intentos ilimitados. Los casos negativos y la concurrencia usan límites explícitos que aplica el servidor, no la interfaz.

## 3. Experiencia de usuario

La página escuchará en el puerto `7284` (configurable). Navegación principal:

1. **Nuevo análisis**: flujo de cuatro pasos.
2. **Resultados**: ejecuciones de la sesión actual del navegador.
3. **Comparar**: cargar dos exportaciones, o la ejecución actual y una exportación.
4. **Conectar con Claude**: instrucciones y descargas para instalar el MCP (ver §8).

### Paso 1 — Objetivo

- Nombre o identificador del equipo.
- IP o FQDN.
- Puerto SSH, con valor inicial `22`.
- Perfil de dispositivo (ver §5), por ejemplo `opengear-om`, `opengear-cm` o `router-generico`.
- Modelo, firmware y etiquetas libres. Si el perfil sabe detectarlos después del login, se rellenan solos.

Antes de ejecutar se hará una validación ligera de DNS, alcance TCP y tiempo de conexión. Un error aquí bloqueará únicamente las pruebas que dependan de ese servicio.

### Paso 2 — Credenciales

- Sin autenticación, para revisar exposición y negociación.
- Usuario y contraseña.
- Usuario y llave privada, con passphrase opcional.
- Certificado SSH.
- `keyboard-interactive`.

Las credenciales las escribe siempre el ingeniero, desde la página o desde Claude. El servidor nunca las guarda: las usa solo durante la ejecución y no aparecen en exportaciones ni en logs.

Para no escribirlas cada vez, la página tendrá un botón **Guardar** que las recuerda en el navegador de ese ingeniero, asociadas al equipo, y un botón **Olvidar** que las borra. Cada ingeniero ve solo las que guardó en su propio navegador.

La interfaz indicará qué pruebas necesitan privilegios normales y cuáles `root` o `sudo`.

### Paso 3 — Pruebas

Las pruebas aparecerán como tarjetas agrupadas por categoría. Cada grupo tendrá `Seleccionar todo`, pero cada prueba podrá activarse individualmente. Habrá perfiles de pruebas predefinidos como archivos: `SSH básico`, `Hardening completo`, `Hash yescrypt` y `Regresión de firmware`.

Antes de ejecutar se mostrará:

- Pruebas seleccionadas.
- Comandos o acciones que se realizarán en el equipo.
- Credenciales y privilegios necesarios, sin mostrar el secreto.
- Número máximo de conexiones, concurrencia, timeout y duración estimada.
- Posible impacto de la prueba.

### Paso 4 — Ejecución y resultados

La ejecución mostrará progreso en tiempo real y permitirá cancelar. Si se cierra la pestaña, la ejecución se cancela y no quedan trabajos huérfanos.

Cada resultado usará uno de estos estados:

- `PASS`: cumple la política.
- `WARN`: funciona, pero requiere revisión.
- `FAIL`: incumple un requisito definido.
- `INFO`: dato de inventario o evidencia sin decisión automática.
- `SKIP`: no se ejecutó porque no aplicaba o faltaba un prerrequisito.
- `ERROR`: la prueba no pudo completarse.

Cada prueba mostrará nombre, estado, resumen, evidencia, duración, política aplicada y recomendación. Un resultado inconcluso se representará como `WARN` o `SKIP`, nunca como un falso `PASS` o `FAIL`.

## 4. Catálogo de pruebas

### A. Conectividad e inventario

- Resolución DNS directa e inversa.
- Conectividad TCP, tiempo de conexión y timeout.
- Banner de servicio y versión declarada.
- Sistema operativo, arquitectura, modelo y firmware cuando el perfil de dispositivo permita detectarlos después del login.
- Fecha y hora remota para detectar desviaciones importantes.

### B. Negociación y postura SSH (sin login)

- Lectura directa del paquete `KEXINIT` del servidor: algoritmos de intercambio de claves, host key, cifrados en ambos sentidos, MACs y compresión. Se registran tal como los anuncia el servidor, sin que el cliente tenga que implementar algoritmos débiles para detectarlos.
- Combinación negociada por defecto.
- Host keys de todos los tipos ofrecidos, con fingerprint SHA-256 (una conexión por tipo).
- Métodos de autenticación anunciados.
- Algoritmos débiles, obsoletos o prohibidos según la política seleccionada.
- **Terrapin (CVE-2023-48795):** vulnerable si el servidor ofrece `chacha20-poly1305@openssh.com` o cifrados CBC con MACs `-etm` y no anuncia `kex-strict-s-v00@openssh.com`.
- **Intercambio de claves post-cuántico:** presencia de `mlkem768x25519-sha256` o `sntrup761x25519-sha512`.
- **Versión declarada frente a CVEs conocidas**, por ejemplo CVE-2024-6387. Se reporta como `INFO` o `WARN`, nunca como `FAIL`, porque el banner no demuestra la versión real.
- Cambio de host key respecto de una exportación de referencia o de un fingerprint esperado introducido a mano.

### C. Pruebas funcionales de autenticación

- Login correcto con contraseña.
- Login correcto con llave privada.
- Login correcto con certificado SSH.
- Login por `keyboard-interactive`.
- Rechazo esperado de contraseña incorrecta.
- Rechazo esperado de llave no autorizada.
- Validación de que una política `publickey only` rechaza contraseñas.
- Validación de cuentas permitidas o bloqueadas según la política.
- Comprobación de acceso directo de `root` según el valor esperado.
- Ejecución de un comando inocuo después del login y cierre de sesión. El comando lo define el perfil de dispositivo (`id` en Linux, un equivalente en la CLI de un router).
- Apertura y cierre repetido de sesiones para detectar fallos intermitentes.
- **Enumeración de usuarios por tiempo:** comparar la latencia de un usuario inexistente con la de un usuario válido con contraseña errónea, con pocos intentos. Con yescrypt la diferencia esperada (100–250 ms) es fácil de medir.

Estas pruebas son de validación, no de fuerza bruta. Los casos negativos usarán una cantidad mínima y explícita de intentos para evitar bloqueos accidentales.

### D. Configuración efectiva de `sshd`

Requiere shell Linux con OpenSSH y privilegios de `root` o `sudo`.

- Configuración efectiva con `sshd -T`.
- Configuración por contexto con `sshd -T -C user=…,host=…,addr=…` para cada usuario u origen relevante de la política. `sshd -T` sin `-C` no aplica los bloques `Match`.
- `PasswordAuthentication`, `PubkeyAuthentication` y `KbdInteractiveAuthentication`.
- `PermitRootLogin`.
- `AllowUsers`, `DenyUsers`, `AllowGroups` y `DenyGroups`.
- `MaxAuthTries`, `LoginGraceTime`, `MaxSessions`, `MaxStartups` y `PerSourcePenalties`.
- Idle timeout y keepalive según la política del producto.
- Uso de PAM.
- Permisos de archivos sensibles de SSH.

La lectura será de solo lectura. Si el equipo no tiene shell Linux u OpenSSH (por ejemplo, un router con CLI propia o un equipo con Dropbear), la prueba se marcará `SKIP` con el motivo exacto y se conservarán las pruebas de red.

### E. Hashes de contraseñas y yescrypt

#### Auditoría de configuración

- Identificar el algoritmo configurado para contraseñas nuevas (`login.defs`, PAM y libxcrypt).
- Identificar el algoritmo y sus parámetros en una cuenta de prueba. En libxcrypt, `yescrypt count 5` corresponde al prefijo `$y$j9T$`.
- El prefijo se extrae **dentro del equipo** y solo el prefijo sale de él. Nunca se copia el hash completo ni el contenido de `/etc/shadow`.
- Confirmar, en una cuenta de prueba, que el cambio de contraseña genera el formato esperado. Impacto: cambio controlado.

#### Benchmark controlado

- Método de medición en el equipo, en este orden, registrando en la evidencia cuál se usó:
  1. Helper en C enlazado contra la libcrypt del propio equipo.
  2. `mkpasswd -m yescrypt -R 5`.
  3. `crypt()` de Perl.
  4. `SKIP` con el motivo.

  Python no sirve: el módulo `crypt` se eliminó en Python 3.13 y los equipos embebidos no suelen tenerlo.
- Generar hashes sintéticos con contraseñas y sales de prueba.
- Medir latencia mínima, media, p50, p95 y máxima.
- Ejecutar primero una prueba individual y después concurrencia limitada.
- Medir memoria máxima aproximada por proceso y memoria libre del equipo.
- Medir también, desde fuera y sin instalar nada, la latencia real de login SSH por contraseña, `su` y `sudo`. Es la métrica con más peso operativo.
- No modificar contraseñas reales ni archivos del sistema. Eliminar los datos sintéticos al terminar.

#### Riesgo de DoS de memoria antes de autenticar

Cada verificación de contraseña con yescrypt reserva unos 16 MiB y ocurre antes de autenticar. El peor caso, sin credenciales, es aproximadamente el tercer valor de `MaxStartups` (100 por defecto) × 16 MiB ≈ 1,6 GiB.

La prueba calculará esa cifra, la comparará con la RAM del equipo y revisará `MaxStartups`, `LoginGraceTime` y `PerSourcePenalties`. Es un cálculo, no una prueba de carga.

#### Línea base

La política inicial tomará como referencia la siguiente comparación proporcionada para el proyecto. Los valores de rendimiento se tratarán como una línea base que debe volver a medirse en cada plataforma, no como valores universales.

| Propiedad | SHA-512-crypt | bcrypt | yescrypt |
|---|---:|---:|---:|
| Parámetro objetivo | 100,000 rounds | cost 12 | count 5 |
| Salt | 96 bits / 16 caracteres por límite del formato | 128 bits | 128 bits |
| Salida cruda | 512 bits / 64 bytes | 184 bits / 23 bytes | 256 bits / 32 bytes |
| Cadena almacenada | 120 caracteres | 60 caracteres | 73 caracteres |
| om1304, Cortex-A53 | 106 ms | 546 ms | 98 ms |
| om2224, AMD GX-412TC | 269 ms | 830 ms | 96 ms |
| cm8148s, Cortex-A9 ×2 | 553 ms | 1,058 ms | 235 ms |
| Memoria por hash | aproximadamente 0, cabe en caché | 4 KiB | 16 MiB |
| Tipo de resistencia | cómputo | cómputo y poca memoria fija | memoria × tiempo |
| Restricción principal | favorable para GPU/ASIC | límite de contraseña de 72 bytes y ataques FPGA | requiere 16 MiB libres por verificación concurrente |

La evaluación deberá confirmar además el impacto operativo esperado:

- Un hash por intento de contraseña en SSH, login de consola, `su`, solicitud de contraseña de `sudo` o desbloqueo de pantalla.
- Dos operaciones durante un cambio de contraseña: verificar la anterior y generar la nueva.
- Ninguna operación en login SSH por llave pública, acciones dentro de una sesión ya abierta, `sudo` dentro de su ventana de caché o uso de un token de sesión válido.
- Con TACACS+, RADIUS o LDAP, la verificación puede ocurrir en el servidor AAA. El reporte deberá indicar dónde se realizó realmente.

Para aceptar `yescrypt count 5` se comprobará simultáneamente:

- Que el formato y el parámetro observados sean los esperados.
- Que el tiempo de autenticación siga dentro del límite definido para el equipo.
- Que exista memoria suficiente para la concurrencia máxima configurada, incluido el peor caso antes de autenticar.
- Que el login, `su`, `sudo` y cambio de contraseña sigan funcionando en los escenarios aplicables.
- Que una autenticación fallida no cause consumo ilimitado ni degradación sostenida.

### F. Concurrencia y estabilidad

- Número de conexiones secuenciales.
- Concurrencia máxima.
- Duración o cantidad total de iteraciones.
- Login, ejecución de un comando inocuo y logout.
- Porcentaje de éxito, errores, latencia y percentiles.
- Separación por método de autenticación.
- Parada automática al superar un umbral de error, latencia o bloqueo.

Este módulo se etiquetará como de impacto medio o alto según los valores elegidos. Los límites salen del perfil de dispositivo y el servidor rechaza cualquier valor por encima del máximo configurado, venga la petición de la web o del MCP.

## 5. Perfiles de dispositivo, perfiles de pruebas y políticas

Todo se define en archivos YAML en `/etc/ssh-auditor/`, con ejemplos versionados en el repositorio. No hay base de datos.

- **Perfil de dispositivo:** tipo de shell (`linux` o `router-cli`), comando inocuo, comandos de detección de modelo y firmware, límites de conexiones y concurrencia, y política aplicable. Nunca contiene credenciales.
- **Perfil de pruebas:** conjunto reutilizable de pruebas y parámetros.
- **Política:** algoritmos permitidos, advertidos y prohibidos; valores esperados de `sshd`; límites de latencia de hash y login; excepciones con motivo y fecha de caducidad. La política base partirá de las políticas de hardening de ssh-audit y añadirá el intercambio de claves post-cuántico.

Ejemplo de perfil de dispositivo:

```yaml
id: opengear-om
nombre: Opengear OM
shell: linux
comando_inocuo: id
deteccion:
  firmware: "<comando que devuelve la versión>"
limites:
  conexiones_max: 50
  concurrencia_max: 4
politica: opengear-base
```

## 6. Comparación de resultados

Casos de uso:

- Mismo equipo, firmware N frente a N+1 (regresión).
- Mismo firmware en distintos modelos.
- Un equipo frente a una exportación de referencia aprobada.

Funcionamiento:

- Entrada: dos exportaciones JSON, o la ejecución actual y una exportación.
- Emparejamiento por ID de prueba y parámetros.
- Por prueba: `Mejoró`, `Empeoró`, `Igual`, `Nueva` o `Desaparecida`.
- Diferencias de evidencia: algoritmos añadidos o eliminados, cambio de host key y cambios en la configuración efectiva.
- Métricas numéricas (latencia, memoria) con umbral configurable para marcar regresión.
- Aviso si las versiones de los plugins o de la política difieren entre las dos exportaciones.
- Opción de reevaluar ambas exportaciones con la misma política antes de comparar.
- El resultado de la comparación también se puede exportar.

Una fase posterior agregará una matriz de N exportaciones, por ejemplo tres modelos o cinco versiones de firmware.

## 7. Resultados, caché y exportación

- **Navegador:** los resultados viven en la memoria de la página y en `sessionStorage` para sobrevivir a una recarga. `localStorage` se usa solo para las credenciales que el ingeniero decida guardar con el botón **Guardar**.
- **Servidor:** caché en RAM de ejecuciones recientes, identificadas por ID, con TTL configurable (24 h por defecto) y tamaño máximo. Nunca se escribe en disco y se pierde al reiniciar. El MCP la usa para consultar y comparar ejecuciones por ID.
- **Exportación:**
  - JSON estable con `schema_version`, reimportable para comparar.
  - HTML autocontenido para compartir.
  - CSV con el resumen de hallazgos.

La exportación incluirá:

- Resumen por estado.
- Objetivo, perfil de dispositivo, modelo y firmware.
- Alcance exacto de la ejecución.
- Resultados por categoría con evidencia y recomendación.
- Pruebas no ejecutadas y motivo.
- Versiones de plugins, política y herramienta para reproducibilidad.

No incluirá contraseñas, passphrases ni llaves privadas.

## 8. MCP: uso desde Claude

El servidor MCP corre en el mismo proceso y puerto que la web: `http://<servidor>:7284/mcp`, con transporte Streamable HTTP.

Herramientas:

| Herramienta | Qué hace |
|---|---|
| `list_tests` | Catálogo de pruebas con parámetros, impacto y prerrequisitos. |
| `list_profiles` | Perfiles de dispositivo, perfiles de pruebas y políticas. |
| `start_scan` | Inicia un análisis y devuelve su ID. |
| `get_scan` | Devuelve el progreso o los resultados de un ID. |
| `cancel_scan` | Cancela un análisis. |
| `compare_scans` | Compara dos IDs o dos exportaciones JSON. |

Reglas:

- La allowlist de redes y los límites los aplica el servidor. Claude no puede superarlos.
- Las pruebas de impacto medio o alto requieren el parámetro explícito `confirm_impact: true`.
- Las credenciales las indica el ingeniero en la conversación y Claude las pasa por parámetro. El servidor no las guarda.
- El servidor MCP publicará `instructions` con el flujo recomendado (negociación, luego autenticación, luego yescrypt) y el significado de cada estado.

### Página "Conectar con Claude"

Disponible en `http://<servidor>:7284/claude`, con la dirección del servidor ya rellenada:

- **Claude Code:** comando listo para copiar y archivo `.mcp.json` descargable para añadirlo a un proyecto.

  ```bash
  claude mcp add --transport http ssh-auditor http://<servidor>:7284/mcp
  ```

- **Claude Desktop:** descarga de un archivo `.mcpb` (MCP Bundle) generado por el servidor, que se instala con doble clic. Contiene un pequeño puente stdio → HTTP en Node con la URL del servidor como valor por defecto en `user_config`. Hace falta porque los conectores remotos personalizados se conectan desde la infraestructura de Anthropic y no alcanzan un servidor de la red interna. Verificar este punto en la Fase 2.
- Ejemplos de uso, por ejemplo: "audita la negociación SSH de 10.0.0.5 con el perfil opengear-om y compárala con el análisis anterior".

## 9. Arquitectura e instalación

### Stack

- Python 3.13, el de Debian 13.
- `asyncssh` para conexiones, autenticación (contraseña, llave, certificado y `keyboard-interactive`) y obtención de host keys sin autenticar.
- Parser propio de `KEXINIT` para leer lo que ofrece el servidor.
- FastAPI y Uvicorn para la API, SSE y archivos estáticos.
- Interfaz en HTML y JS sin paso de compilación (htmx o JS plano).
- SDK oficial `mcp` montado en la misma aplicación.
- PyYAML y Pydantic para perfiles, políticas y esquema de exportación.
- ssh-audit solo como referencia en los tests de laboratorio, no como dependencia de ejecución.

### Estructura del repositorio

```text
ssh_auditor/
  engine/      ejecución, límites, cancelación y caché en RAM
  plugins/     una prueba por módulo (collect + evaluate)
  policy/      carga de YAML y evaluación
  compare/     diferencias entre exportaciones
  web/         rutas FastAPI, SSE y HTML/JS estático
  mcp/         servidor MCP y generación de .mcp.json y .mcpb
config/        perfiles y políticas de ejemplo
deploy/        unidad systemd e install.sh
tests/         unitarios y laboratorio con sshd de configuración conocida
```

### Contrato de plugin

```python
class Plugin(Protocol):
    meta: Meta  # id, versión, categoría, impacto, prerrequisitos, privilegios, timeout

    async def collect(self, ctx: Context) -> Evidence: ...

    def evaluate(self, evidence: Evidence, policy: Policy) -> list[Finding]: ...
```

Agregar una prueba consistirá en crear un módulo en `plugins/` y su sección de política, sin editar el motor, la web ni el MCP. Ambas entradas leen el catálogo del registro de plugins.

### Despliegue en Debian 13

- Servicio systemd `ssh-auditor.service`, igual que las demás herramientas del servidor.
- Código en `/opt/ssh-auditor` con un entorno virtual y dependencias fijadas con hashes.
- Configuración en `/etc/ssh-auditor/`: `config.yaml`, perfiles y políticas.
- Escucha en `0.0.0.0:7284` (configurable), solo accesible desde la red interna, sin token.
- Atiende a varios ingenieros a la vez. Cada análisis es independiente y los límites por equipo se aplican sumando todos los análisis activos contra él.
- Usuario de sistema dedicado y endurecimiento de systemd: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` y `MemoryMax`.
- Una línea en journald por análisis (IP de origen, objetivo, pruebas y hora), sin resultados.
- `deploy/install.sh` instala `python3` y `python3-venv`, crea el usuario y el entorno virtual, copia la configuración de ejemplo y habilita el servicio.
- Sin base de datos, Redis, contenedores ni reverse proxy en esta versión.

## 10. Seguridad de la propia herramienta

- Allowlist de redes destino (CIDR) en `config.yaml`. El servidor rechaza cualquier otro objetivo, venga de la web o del MCP.
- Límites globales y por objetivo de conexiones y concurrencia, para que varios ingenieros probando el mismo equipo no sumen más carga de la permitida.
- Timeout y cancelación real de conexiones.
- Solo red interna. Sin token en la web ni en el MCP.
- El servidor no guarda credenciales en ningún archivo, log, caché ni exportación.
- Validación estricta de entradas y límites de tamaño, incluida la importación de exportaciones JSON.
- Exportaciones sin contraseñas, passphrases ni llaves privadas.
- Dependencias fijadas y revisadas con `pip-audit`.

## 11. API HTTP

API versionada bajo `/api/v1`. Operaciones mínimas:

- `GET /tests`: catálogo de pruebas y parámetros.
- `GET /profiles`: perfiles de dispositivo, perfiles de pruebas y políticas.
- `POST /scans`: inicia un análisis y devuelve su ID.
- `GET /scans/{id}/events`: progreso por SSE.
- `GET /scans/{id}`: estado y resultados.
- `DELETE /scans/{id}`: cancela.
- `GET /scans/{id}/export?format=json|html|csv`: exportación.
- `POST /compare`: compara dos IDs o dos exportaciones.

Este contrato podrá reutilizarse para las demás herramientas cuando exista el portal central.

## 12. Fases de implementación

### Fase 0 — Laboratorio y política

- Equipos de laboratorio: om1304, om2224, cm8148s y al menos un router.
- Contenedores con `sshd` de configuraciones buenas y malas conocidas (OpenSSH antiguo, Dropbear, algoritmos débiles) para tests automáticos.
- Política base y perfiles de dispositivo iniciales.
- Confirmar `$y$j9T$` y el método de benchmark disponible en cada plataforma.

### Fase 1 — Base y negociación

- Motor, registro de plugins, resultados normalizados y caché en RAM.
- Pruebas A y B, sin login.
- Web con el flujo de cuatro pasos, progreso en tiempo real y cancelación.
- Exportación JSON, HTML y CSV, e importación.
- Comparación de dos exportaciones.
- Servicio systemd en Debian 13 en el puerto 7284.

### Fase 2 — MCP

- Servidor MCP en `/mcp` con las herramientas de §8.
- Página "Conectar con Claude", `.mcp.json` y `.mcpb`.
- Verificación de la instalación en Claude Code y Claude Desktop.

### Fase 3 — Autenticación y configuración

- Pruebas C y D.
- Botones **Guardar** y **Olvidar** credenciales en el navegador.
- Detección de modelo y firmware según el perfil de dispositivo.

### Fase 4 — yescrypt y concurrencia

- Pruebas E y F.
- Perfil de aceptación `yescrypt count 5`.

### Después

- Matriz de N exportaciones.
- Integración en el portal central cuando exista.

## 13. Criterios de aceptación

### Fase 1

- Se instala como servicio systemd y responde en el puerto 7284.
- Muestra KEX, host keys con fingerprint, cifrados, MACs y métodos de autenticación anunciados de un Opengear real.
- Detecta Terrapin y la ausencia de intercambio de claves post-cuántico en un `sshd` de laboratorio vulnerable.
- Exporta JSON y HTML, reimporta el JSON y compara dos ejecuciones mostrando algoritmos añadidos o eliminados y cambio de host key.
- Rechaza objetivos fuera de la allowlist.

### Fase 2

- Desde Claude Code, después de ejecutar el comando de la página, Claude lista las pruebas, lanza un análisis y compara dos ejecuciones.
- El `.mcpb` se instala en Claude Desktop y funciona contra el servidor interno.
- El servidor rechaza por MCP una concurrencia superior al límite.

### Fase 3

- Login por contraseña, llave, certificado y `keyboard-interactive` sin incluir secretos en la exportación.
- Los casos negativos limitados reconocen un rechazo esperado como `PASS`.
- Lee la configuración efectiva, incluidos los bloques `Match`, con `sshd -T -C`.
- Marca `SKIP` con el motivo en equipos sin shell Linux u OpenSSH.

### Fase 4

- Valida `$y$j9T$` sin sacar el hash del equipo.
- Ejecuta un benchmark sintético sin cambiar contraseñas reales.
- Calcula el riesgo de DoS de memoria antes de autenticar.
- Ejecuta concurrencia con límites, parada automática y cancelación.
- Compara latencias entre dos firmwares y marca regresión según el umbral.

## 14. Decisiones configurables

- Puerto e interfaz de escucha.
- Allowlist de redes destino.
- Límites globales, por objetivo y por perfil de dispositivo.
- Política criptográfica por producto.
- Algoritmos permitidos, advertidos y prohibidos.
- Límites aceptables de latencia para hash y login.
- Umbrales de regresión en comparaciones.
- TTL y tamaño de la caché en RAM.
- Comandos de solo lectura que puede ejecutar una cuenta con `sudo`.
- Idioma del reporte: inicialmente español, con la evidencia en inglés técnico.
