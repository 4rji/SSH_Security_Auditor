# Fase 3 — Decisiones e implementación (2026-10-09)

Este documento conserva las decisiones de la Fase 3 y describe el contrato que quedó
implementado. El diseño de referencia sigue siendo `instrucciones.md`: §3 paso 2, §4 C
y D, §12 Fase 3 y §13 criterios de la Fase 3.

## Alcance y orden

La Fase 3 se implementó en dos ciclos dependientes:

1. **3a — Credenciales y pruebas C (autenticación).** Incluye los botones **Guardar** y **Olvidar** de la web.
2. **3b — Pruebas D y detección.** Configuración efectiva de solo lectura con `sshd -T -C`, `SKIP` con motivo en equipos sin shell Linux u OpenSSH, y detección de modelo y firmware según el perfil de dispositivo.

La 3b usa el login de la 3a, así que va después.

## Estado implementado

### 3a — Credenciales y autenticación

- `Credentials` acepta `password`, `private_key`, `certificate` y
  `keyboard_interactive`. Un certificado requiere también su llave privada; una llave
  puede llevar frase de paso; las respuestas interactivas conservan el orden de los
  prompts.
- La petición REST y `start_scan` reciben el mismo campo `credentials`. El campo es de
  entrada y se excluye de la serialización de `ScanRequest`; no existe un campo
  equivalente en resultados, eventos, caché ni exportaciones.
- Cada conexión fuerza el método elegido y deshabilita llaves locales, agente SSH,
  configuración del cliente, GSSAPI y demás credenciales ambientales. Las llaves y los
  certificados se importan desde memoria.
- El método `none` puede llevar solo `username` para los casos negativos que no
  necesitan una credencial válida. La web conserva y envía ese usuario sin exigir una
  contraseña o llave ficticia.
- Las pruebas positivas son `auth_password`, `auth_private_key`, `auth_certificate` y
  `auth_keyboard_interactive`. Tras autenticar ejecutan `safe_command` del perfil y
  cierran la sesión.
- Los casos negativos son `auth_reject_wrong_password`,
  `auth_reject_unauthorized_key` y `auth_publickey_only`. Cada uno abre una sola
  conexión; un rechazo esperado produce `PASS` y una aceptación produce `FAIL`.
- `auth_repeated_sessions` abre, usa y cierra tres sesiones en secuencia. Los casos
  negativos y esta prueba tienen impacto `medium`, requieren `confirm_impact` y no
  aparecen seleccionados por defecto en la web.
- Las excepciones que cruzan el límite del plugin se reducen a mensajes permitidos o al
  nombre de su clase. No se devuelve el texto arbitrario de excepciones que pueda
  contener una contraseña, llave o respuesta interactiva.
- El motor redacta además los valores secretos si un equipo remoto los devuelve en
  stdout, stderr, evidencia, hallazgos o mensajes de progreso, antes de crear el
  resultado, emitir SSE o escribir en la caché.

### 3b — Detección y configuración efectiva

- `device_inventory` ejecuta únicamente los comandos `detection.model` y
  `detection.firmware` del perfil. Cada comando y `safe_command` debe ser una sola línea
  de hasta 512 caracteres. La salida de detección se limita a 4096 bytes y el valor
  normalizado a 512 caracteres.
- Modelo, firmware y etiquetas forman parte de la petición y del resultado. Cuando el
  usuario no proporciona modelo o firmware, los valores detectados completan el
  resultado y los campos de la web.
- La web muestra el tipo de shell, `safe_command` y los comandos de detección del perfil
  antes del análisis. Un perfil es configuración confiable: esos comandos se ejecutan
  tal como están declarados y deben ser de solo lectura.
- `sshd_config` solo aplica a un perfil con shell `linux`, credenciales autenticadas,
  Linux remoto, un binario OpenSSH `sshd` y acceso como `root` o mediante `sudo -n`.
  Cualquier condición de aplicabilidad ausente produce `SKIP` con el motivo concreto.
- Toda la recolección de configuración comparte una sola conexión autenticada. El
  binario `sshd` debe resolverse desde el PATH del sistema, pertenecer a root y no ser
  escribible por grupo u otros antes de que pueda ejecutarse con `sudo`.
- La recolección ejecuta `sshd -T` y, por cada contexto de la política, añade
  `-C user=…`, `-C host=…` y `-C addr=…` (más `-C invalid-user` cuando corresponda).
  Un contexto tiene `name`, `user`, `host`, `addr`, `invalid_user` opcional y sus
  valores `expected`; los nombres deben ser únicos.
- Se comparan los valores efectivos de autenticación, acceso de cuentas, root,
  límites, keepalive, timeouts y PAM. También se comprueban propietario y permisos de
  `sshd_config`, fragmentos de `sshd_config.d` y llaves privadas de host. Toda la
  recolección es de solo lectura.
- Las cuentas permitidas o bloqueadas y el acceso de `root` se validan comparando los
  valores y patrones efectivos de `AllowUsers`, `DenyUsers`, `AllowGroups`,
  `DenyGroups` y `PermitRootLogin` con la expectativa del contexto. No se intentan
  logins adicionales, no se resuelve pertenencia NSS a grupos y no se calcula un
  veredicto abstracto `expected_access`; la política expresa las directivas esperadas.

### Interfaz y catálogo

- **Guardar** persiste explícitamente las credenciales en texto claro bajo
  `sshAuditor.credentials.v1`, indexadas por `host:port` normalizado. **Olvidar** borra
  solo la entrada de ese equipo y limpia el formulario.
- En una comparación en vivo, el segundo equipo recibe únicamente sus propias
  credenciales guardadas; el formulario actual se reutiliza solo cuando host y puerto
  coinciden.
- El catálogo de la web y del MCP expone método de credencial, privilegio requerido y
  acciones remotas de cada prueba para que el operador pueda revisar el impacto antes
  de autorizarlo.

## Validación realizada

Hay pruebas automatizadas de los cuatro métodos de autenticación, rechazos esperados,
sesiones repetidas, cancelación, límites de salida, detección, análisis de `sshd -T`,
permisos y omisión de secretos en modelos y resultados. Contraseña, llave privada,
certificado y `keyboard-interactive` se prueban de extremo a extremo contra servidores
AsyncSSH locales controlados; el caso de certificado comprueba además que una CA
rechazada no pueda caer silenciosamente a la llave sin certificado. Esta validación no
equivale a una prueba manual contra equipos físicos, firmwares reales o clientes Claude;
`sshd -T -C` se prueba con salidas controladas, no contra un proceso `sshd` real. Esas
verificaciones externas no se dan por realizadas aquí.

Dos límites quedan explícitos para una fase posterior:

- Las conexiones autenticadas no fijan todavía una host key esperada. La resolución de
  DNS sí se hace una sola vez y la conexión usa la IP concreta aceptada por la allowlist,
  pero la identidad criptográfica del servidor no queda anclada; las credenciales de
  esta fase son para la red interna de laboratorio autorizada.
- Los permisos cubren las rutas estándar `/etc/ssh/sshd_config`,
  `/etc/ssh/sshd_config.d/*.conf` y `/etc/ssh/ssh_host_*_key`. Un `Include` o `HostKey`
  fuera de `/etc/ssh` requiere ampliar la recolección en otra fase.

## Decisiones

- **Credenciales en el navegador:** **Guardar** las deja en `localStorage` tal cual, sin cifrado ni frase de desbloqueo, asociadas al equipo. **Olvidar** las borra. Son credenciales de laboratorio conocidas y repetidas entre equipos.
- **Credenciales hacia el servidor:** lo más simple, un campo más en la petición de análisis, igual por la web y por el MCP (`start_scan`). Sin almacén temporal, tokens ni cifrado. Lo único obligatorio (§13) es que no aparezcan en el resultado ni en las exportaciones.
- **Medición por tiempo de §4 C:** queda para más adelante, porque no está en los criterios de aceptación de la Fase 3 (§13).
- **Cuentas permitidas o bloqueadas y acceso directo de `root`:** se validan en la 3b leyendo la configuración efectiva con `sshd -T -C`, no probando logins.

## Pendientes heredados de la Fase 2

Resuelto el 2026-10-09: el paquete se renombró a `ssh_auditor/mcp_server` (ya no tapa al SDK `mcp`); las `instructions` del MCP se generan desde el catálogo de pruebas; hay tests de que cancelar cierra la conexión y no deja resultado, y de que un cliente que se desconecta no detiene el análisis; `pip-audit` sobre los 46 paquetes instalados: sin vulnerabilidades conocidas.

Queda:

- Verificación manual en Claude Code y Claude Desktop (ver `2026-10-08-fase2-mcp.md`, Task 7).
- Revisar `allow_networks: 0.0.0.0/0` en `config/config.example.yaml`.
- Línea en journald por análisis (§9) y caché con tamaño máximo (§7), pendientes desde la Fase 1.
