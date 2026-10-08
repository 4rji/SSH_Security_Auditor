# Plan de desarrollo — SSH Security Auditor

## 1. Objetivo

Crear una aplicación web para que los ingenieros puedan validar de forma controlada la seguridad y el comportamiento de uno o varios servidores. La primera versión se centrará en SSH, autenticación, configuración de hashes de contraseñas y TLS, pero la arquitectura deberá permitir agregar nuevas pruebas sin modificar el núcleo de la aplicación.

La herramienta deberá permitir:

- Registrar los datos generales del objetivo una sola vez.
- Elegir exactamente qué pruebas ejecutar.
- Probar desde uno o varios puntos de red mediante runners locales o remotos.
- Usar autenticación por contraseña, llave privada, certificado SSH o `keyboard-interactive`.
- Ejecutar verificaciones de configuración, pruebas funcionales y pruebas de concurrencia controladas.
- Presentar resultados claros con evidencia, explicación y acción recomendada.
- Comparar resultados contra una política aprobada y contra ejecuciones anteriores.
- Exportar un reporte sin incluir contraseñas, llaves privadas ni hashes sensibles.

TLS no forma parte de SSH. Se manejará como otro módulo dentro de la misma herramienta para revisar servicios HTTPS, APIs, interfaces administrativas u otros puertos TLS del mismo equipo.

## 2. Experiencia de usuario propuesta

No conviene llenar la interfaz con muchas pestañas independientes. Se usará un flujo de cuatro pasos y una navegación principal pequeña.

### Navegación principal

1. **Nuevo análisis**: crear y ejecutar una evaluación.
2. **Resultados**: consultar ejecuciones, evidencia y diferencias.
3. **Objetivos y perfiles**: guardar servidores, políticas y conjuntos de pruebas.
4. **Administración**: usuarios, runners, límites, secretos e integraciones.

### Flujo de un análisis

#### Paso 1 — Objetivo

Campos generales:

- Nombre o identificador del equipo.
- IP o FQDN.
- Puerto SSH, con valor inicial `22`.
- Puertos TLS que se quieran revisar, por ejemplo `443` o `8443`.
- SNI/hostname esperado para TLS.
- Entorno: laboratorio, desarrollo, QA o producción.
- Modelo, plataforma y arquitectura, cuando se conozcan.
- Etiquetas: producto, versión, equipo responsable y ubicación.
- Runner u origen de red desde el que se hará la prueba.

La aplicación hará primero una validación ligera de resolución DNS, alcance TCP y tiempo de conexión. Un error aquí deberá impedir únicamente las pruebas que dependan de ese servicio.

#### Paso 2 — Credenciales

Métodos seleccionables:

- Sin autenticación, para revisar exposición y negociación.
- Usuario y contraseña.
- Usuario y llave privada, con passphrase opcional.
- Certificado SSH.
- `keyboard-interactive`.
- Credencial guardada en un gestor de secretos, en una fase posterior.

Las credenciales introducidas para una ejecución serán temporales. No se guardarán en la base de datos, historial, logs ni reportes. La interfaz deberá dejar claro cuándo una prueba necesita privilegios normales o `sudo`.

#### Paso 3 — Pruebas

Las pruebas aparecerán como tarjetas agrupadas por categoría. Cada grupo tendrá `Seleccionar todo`, pero cada prueba podrá activarse individualmente. También se podrán guardar perfiles como `SSH básico`, `Hardening completo`, `Hash yescrypt`, `TLS completo` o `Regresión de autenticación`.

Antes de ejecutar se mostrará:

- Pruebas seleccionadas.
- Comandos o acciones que se realizarán en el objetivo.
- Credenciales y privilegios necesarios, sin mostrar el secreto.
- Número máximo de conexiones, concurrencia, timeout y duración estimada.
- Runners seleccionados.
- Posible impacto de la prueba.

#### Paso 4 — Ejecución y resultados

La ejecución mostrará progreso en tiempo real y permitirá cancelar trabajos pendientes o activos. Cada resultado usará uno de estos estados:

- `PASS`: cumple la política.
- `WARN`: funciona, pero requiere revisión.
- `FAIL`: incumple un requisito definido.
- `INFO`: dato de inventario o evidencia sin decisión automática.
- `SKIP`: no se ejecutó porque no aplicaba o faltaba un prerrequisito.
- `ERROR`: la prueba no pudo completarse.

Cada prueba deberá mostrar nombre, estado, resumen, evidencia sanitizada, duración, runner, política aplicada y recomendación. Los resultados `inconclusive` se representarán como `WARN` o `SKIP`, nunca como un falso `PASS` o `FAIL`.

## 3. Catálogo inicial de pruebas

### A. Conectividad e inventario

- Resolución DNS directa e inversa.
- Conectividad TCP al puerto indicado.
- Tiempo de conexión y timeout.
- Banner de servicio y versión declarada.
- Detección básica del sistema operativo y arquitectura cuando el usuario autenticado tenga acceso.
- Fecha y hora remota para detectar desviaciones importantes.
- Identificación del runner y ruta/origen desde el que se hizo la prueba.

### B. Negociación y postura SSH

- Versiones del protocolo SSH aceptadas.
- Algoritmos de intercambio de claves ofrecidos y negociados.
- Algoritmos de host key.
- Cifrados del cliente al servidor y del servidor al cliente.
- MACs y modos AEAD.
- Compresión.
- Fingerprint de las host keys.
- Cambio inesperado de host key respecto de una línea base confiable.
- Métodos de autenticación anunciados.
- Comprobación de algoritmos débiles, obsoletos o prohibidos por la política seleccionada.
- Captura de la combinación negociada por defecto y de alternativas permitidas.
- Revisión de configuración efectiva de `sshd` cuando exista acceso con los privilegios necesarios.

La aplicación separará claramente lo observado desde la red de lo leído dentro del equipo. No asumirá que el banner representa la configuración real.

### C. Pruebas funcionales de autenticación SSH

- Login correcto con contraseña.
- Login correcto con llave privada.
- Login correcto con certificado SSH.
- Login por `keyboard-interactive`.
- Rechazo esperado de contraseña incorrecta.
- Rechazo esperado de llave no autorizada.
- Validación de que una política `publickey only` rechaza contraseñas.
- Validación de cuentas permitidas o bloqueadas según la política.
- Comprobación de acceso directo de `root` según el valor esperado.
- Ejecución de un comando inocuo después del login, por ejemplo obtener identidad y cerrar sesión.
- Apertura y cierre repetido de sesiones para detectar fallos intermitentes.
- Varias conexiones simultáneas con límites definidos por el usuario.
- Comparación de resultados desde varios runners o segmentos de red.

Estas pruebas son de validación, no de fuerza bruta. No se implementarán password spraying, listas de contraseñas ni intentos ilimitados. Los casos negativos usarán una cantidad mínima y explícita de intentos para evitar bloqueos accidentales.

### D. Configuración de autenticación y sesiones

- `PasswordAuthentication`, `PubkeyAuthentication` y `KbdInteractiveAuthentication` efectivos.
- `PermitRootLogin`.
- `AllowUsers`, `DenyUsers`, `AllowGroups` y `DenyGroups`.
- `MaxAuthTries`, `LoginGraceTime`, `MaxSessions` y `MaxStartups`.
- Idle timeout y keepalive según la política del producto.
- Uso de PAM.
- Reglas aplicadas mediante bloques `Match`.
- Permisos de archivos sensibles de SSH que el usuario autorizado pueda consultar.
- Presencia de rate limiting, bloqueo o protección equivalente cuando sea requisito.

La lectura de configuración será de solo lectura. Si la herramienta no puede obtener la configuración efectiva, conservará la prueba de red y marcará la revisión interna como `SKIP` o `WARN` con el motivo exacto.

### E. Hashes de contraseñas y yescrypt

Este módulo tendrá dos modos separados.

#### Auditoría de configuración

- Identificar el algoritmo configurado para contraseñas nuevas.
- Identificar el algoritmo y sus parámetros en una cuenta de prueba autorizada.
- Validar que la configuración objetivo sea `yescrypt` con factor/count `5`.
- Revisar la configuración relevante de PAM, `login.defs` y la biblioteca criptográfica disponible.
- Confirmar que el cambio de contraseña genera el formato esperado.
- Reportar únicamente algoritmo, parámetros y longitud; nunca copiar el hash completo ni el contenido de `/etc/shadow`.

#### Benchmark controlado

- Generar hashes sintéticos con contraseñas y sales de prueba.
- Medir latencia mínima, promedio, percentiles y máxima.
- Ejecutar primero una prueba individual y después concurrencia limitada.
- Medir memoria máxima aproximada por proceso y memoria libre del equipo.
- No modificar contraseñas reales ni archivos del sistema.
- Eliminar los datos sintéticos al terminar.

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
- Con TACACS+, RADIUS o LDAP, la verificación puede ocurrir en el servidor AAA; el reporte deberá indicar dónde se realizó realmente.

Para aceptar `yescrypt count 5`, la primera versión deberá comprobar simultáneamente:

- Que el formato y el parámetro observados sean los esperados.
- Que el tiempo de autenticación siga dentro del límite definido para el equipo.
- Que exista memoria suficiente para la concurrencia máxima configurada.
- Que el login, `su`, `sudo` y cambio de contraseña sigan funcionando en los escenarios aplicables.
- Que una autenticación fallida no cause consumo ilimitado ni degradación sostenida.

### F. TLS

El usuario elegirá cada puerto TLS y podrá indicar SNI. El módulo incluirá:

- Negociación por defecto: versión, cipher suite y grupo/llave efímera.
- Matriz de TLS 1.0, 1.1, 1.2 y 1.3.
- Distinción entre protocolo rechazado y prueba que el cliente local no pudo ejecutar.
- Cipher suites aceptadas por versión.
- Detección de cifrados AEAD y algoritmos débiles definidos por la política.
- Certificado leaf y cadena presentada.
- Subject, issuer, SAN, número de serie, fechas y días restantes.
- Validación de hostname, cadena de confianza y expiración.
- Algoritmo de firma y tamaño/tipo de llave pública.
- Fingerprint y pin SPKI para línea base y detección de cambios.
- Estado básico de revocación cuando la información necesaria esté disponible.
- ALPN negociado cuando aplique.

El reporte deberá producir mensajes equivalentes a:

```text
[PASS] TLS 1.3 was negotiated by default.
[PASS] An AEAD cipher was negotiated: TLS_AES_256_GCM_SHA384.
[WARN] TLS 1.0 probe is inconclusive because the local client could not run it.
[INFO] Fingerprint and SPKI pin can be used for trusted-baseline drift detection.
```

### G. Pruebas de concurrencia y estabilidad

- Número de conexiones secuenciales.
- Concurrencia máxima.
- Duración o cantidad total de iteraciones.
- Login, ejecución de un comando inocuo y logout.
- Porcentaje de éxito, errores, latencia y percentiles.
- Separación por método de autenticación.
- Comparación por runner y origen de red.
- Parada automática al superar un umbral de error, latencia o bloqueo.

Este módulo se etiquetará como de impacto medio o alto según los valores elegidos. Producción usará límites conservadores por defecto y requerirá que el usuario confirme el alcance dentro de la propia ejecución.

## 4. Arquitectura propuesta

### Componentes

1. **Web UI**: interfaz responsive para configurar y consultar análisis.
2. **API**: validación de entradas, autorización, políticas, historial y reportes.
3. **Scheduler**: divide un análisis en trabajos y los asigna a runners.
4. **Runner**: ejecuta plugins de pruebas con timeout, límites y usuario sin privilegios.
5. **Base de datos**: objetivos, perfiles, políticas, metadatos y resultados sanitizados.
6. **Cola de trabajos**: ejecución asíncrona, cancelación y reintentos controlados.
7. **Canal de eventos**: Server-Sent Events o WebSocket para progreso en tiempo real.
8. **Reverse proxy**: HTTPS, autenticación y límites de petición para la propia aplicación.

### Despliegue recomendado para Debian 13

Usar contenedores administrados con un archivo Compose compatible. Podman rootless será la opción preferida cuando la infraestructura lo permita; Docker Compose podrá mantenerse como alternativa si ya es el estándar del equipo.

Servicios iniciales:

- `web-api`.
- `worker-local`.
- `postgres`.
- `redis` para trabajos y eventos.
- `reverse-proxy`.

Los workers adicionales usarán la misma imagen y se podrán desplegar en otras redes. El scheduler permitirá elegir `local`, `lab`, `management`, `customer-site` u otros runners registrados. No se montará el socket de Docker/Podman dentro de la aplicación web.

Cada runner deberá:

- Tener identidad propia y comunicación autenticada con el servidor central.
- Anunciar capacidades y versiones de OpenSSH/OpenSSL disponibles.
- Aplicar allowlists de redes y puertos.
- Ejecutar con filesystem temporal, límites de CPU/memoria y timeout.
- Eliminar secretos y archivos temporales al finalizar.
- Enviar solamente resultados y evidencia sanitizada.

### Diseño extensible de plugins

Cada prueba se implementará como un plugin con un contrato común:

- ID estable y versión.
- Categoría, nombre y descripción.
- Parámetros de entrada y valores iniciales.
- Prerrequisitos y privilegios requeridos.
- Nivel de impacto.
- Timeout y límites permitidos.
- Función de ejecución.
- Evidencia sanitizada.
- Regla de evaluación.
- Remediación recomendada.

Agregar una prueba nueva deberá consistir en crear el plugin, su política y su presentación, sin editar el scheduler ni el modelo general de resultados.

## 5. Modelo de datos mínimo

- **Target**: host, puertos, entorno, plataforma, etiquetas y propietario.
- **CredentialReference**: tipo y referencia temporal; nunca el secreto en texto claro.
- **Runner**: identidad, ubicación, capacidades, estado y allowlists.
- **TestDefinition**: ID, versión, categoría, parámetros y nivel de impacto.
- **Policy**: valores esperados, severidad y excepciones documentadas.
- **TestProfile**: conjunto reutilizable de pruebas y parámetros.
- **Scan**: objetivo, usuario solicitante, perfil, tiempos y estado.
- **TestRun**: plugin, runner, resultado, métricas y evidencia sanitizada.
- **Baseline**: fingerprints, pins y resultados aprobados para comparar drift.
- **AuditEvent**: quién creó, ejecutó, canceló, exportó o modificó una política.

## 6. Seguridad de la propia herramienta

- Autenticación de usuarios y RBAC con roles de administrador, operador y lector.
- Inventario y allowlist de objetivos autorizados.
- Protección CSRF, validación estricta de entradas y límites de tamaño.
- Cifrado TLS entre navegador, servidor y runners.
- Secretos solo en memoria o mediante referencias de un gestor de secretos.
- Redacción automática de contraseñas, passphrases, llaves privadas, tokens y hashes.
- Logs estructurados sin datos sensibles.
- Registro de auditoría inmutable para acciones importantes.
- Límites globales y por usuario para conexiones y concurrencia.
- Timeout y cancelación real de procesos.
- Imágenes de contenedor fijadas por digest, ejecutadas como usuario no root y analizadas por vulnerabilidades.
- Dependencias fijadas, SBOM del producto y proceso de actualización.
- Separación entre pruebas de lectura, autenticación, cambio controlado y carga.

La herramienta solo deberá operar contra activos autorizados. Las pruebas de login negativo y concurrencia estarán limitadas para evitar que se conviertan accidentalmente en fuerza bruta o denegación de servicio.

## 7. Reportes

Formatos iniciales:

- Vista web interactiva.
- JSON estable para integraciones.
- HTML descargable y autocontenido.
- CSV para el resumen de hallazgos.

Una fase posterior podrá agregar PDF y envío a sistemas de tickets. El reporte incluirá:

- Resumen ejecutivo y porcentaje por estado.
- Datos del objetivo y runner.
- Alcance exacto de la ejecución.
- Resultados por categoría.
- Evidencia técnica sanitizada.
- Recomendación y severidad.
- Pruebas no ejecutadas y motivo.
- Comparación con la línea base anterior.
- Versiones de plugins y herramientas usadas para reproducibilidad.

## 8. API inicial

La interfaz web consumirá una API versionada. Operaciones mínimas:

- Crear y consultar objetivos.
- Consultar pruebas disponibles y sus parámetros.
- Crear y consultar perfiles y políticas.
- Validar un análisis antes de iniciarlo.
- Iniciar, seguir y cancelar un análisis.
- Consultar resultados y evidencia.
- Comparar dos ejecuciones.
- Exportar un reporte.
- Registrar y consultar runners.

La API no devolverá secretos después de recibirlos. Los campos sensibles serán de escritura única y se sustituirán por un indicador como `credential_received: true`.

## 9. Fases de implementación

### Fase 0 — Definición y laboratorio

- Convertir este plan en requisitos verificables.
- Crear una política inicial para SSH, yescrypt y TLS.
- Preparar servidores de laboratorio con configuraciones buenas y malas conocidas.
- Definir límites seguros de concurrencia para cada clase de equipo.
- Confirmar la representación exacta de `yescrypt count 5` en las plataformas objetivo.

### Fase 1 — Base funcional

- Aplicación web, API, base de datos y worker local.
- Alta de objetivos y flujo de cuatro pasos.
- Motor de plugins y resultados normalizados.
- Conectividad, inventario y negociación SSH sin login.
- Progreso en tiempo real, cancelación y reporte HTML/JSON.
- Seguridad básica, RBAC y auditoría.

### Fase 2 — Autenticación SSH

- Contraseña, llave, certificado y `keyboard-interactive`.
- Casos positivos y negativos controlados.
- Lectura de configuración efectiva con permisos explícitos.
- Pruebas secuenciales y concurrencia limitada.
- Sanitización automática de toda evidencia.

### Fase 3 — yescrypt y rendimiento

- Auditoría de configuración y parámetros.
- Benchmark sintético en el equipo objetivo.
- Escenarios de login, `su`, `sudo` y cambio de contraseña.
- Métricas de latencia, memoria y concurrencia.
- Perfil de aceptación `yescrypt count 5`.

### Fase 4 — TLS

- Negociación por defecto y matriz de protocolos.
- Cipher suites, certificado, cadena, hostname y expiración.
- Fingerprint y pin SPKI como baseline.
- Tratamiento correcto de pruebas inconclusas por limitaciones del cliente.

### Fase 5 — Runners distribuidos y operación

- Registro seguro de runners remotos.
- Comparación desde varios segmentos de red.
- Perfiles, baselines y detección de drift.
- Integración con gestor de secretos y SSO.
- Exportaciones adicionales e integración con tickets/pipeline.

## 10. Criterios de aceptación de la primera entrega

- Puede registrar un objetivo y probar conectividad SSH.
- Permite seleccionar pruebas individuales o un perfil.
- Negocia SSH y muestra algoritmos, host key y métodos de autenticación.
- Ejecuta login por contraseña y llave sin guardar los secretos.
- Ejecuta casos negativos limitados y reconoce un rechazo esperado como `PASS`.
- Ejecuta varias conexiones con límites, timeout y botón de cancelación.
- Distingue evidencia remota de configuración leída dentro del objetivo.
- Valida configuración `yescrypt count 5` y ejecuta un benchmark sintético sin cambiar contraseñas reales.
- Revisa un puerto TLS y genera negociación por defecto, matriz, certificado, fingerprint y SPKI pin.
- Distingue fallo del servidor de incapacidad del cliente para ejecutar una prueba.
- Produce resultados normalizados y un reporte HTML/JSON sin secretos.
- Mantiene auditoría de quién ejecutó qué prueba, contra qué objetivo y desde qué runner.
- Se despliega en Debian 13 mediante contenedores y puede incorporar runners remotos después.

## 11. Decisiones que deben quedar configurables

- Política criptográfica por producto o cliente.
- Límites aceptables de latencia para hash y login.
- Concurrencia máxima por clase de equipo.
- Algoritmos permitidos, advertidos y prohibidos.
- Tiempo mínimo restante de certificados.
- Redes, hosts y puertos autorizados para cada runner.
- Retención de resultados y eventos de auditoría.
- Qué comandos de solo lectura puede ejecutar una cuenta con `sudo`.
- Idioma del reporte; inicialmente español e inglés técnico en la evidencia.

Este orden entrega valor desde la primera fase y deja el sistema preparado para incorporar nuevas pruebas de seguridad, rendimiento o regresión como plugins independientes.
