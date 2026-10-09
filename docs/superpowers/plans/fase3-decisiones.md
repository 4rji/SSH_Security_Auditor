# Fase 3 — Decisiones tomadas (2026-10-09)

Notas para retomar la Fase 3. Todavía no hay plan de implementación escrito.

## Diseño

- El diseño es `instrucciones.md`: §3 paso 2, §4 C y D, §12 Fase 3 y §13 criterios de la Fase 3. No se escribe una spec aparte: el plan sale directo de ahí, como el de la Fase 2.

## Alcance y orden

La Fase 3 se parte en dos ciclos, cada uno con su plan, ejecución y revisión:

1. **3a — Credenciales y pruebas C (autenticación).** Incluye los botones **Guardar** y **Olvidar** de la web.
2. **3b — Pruebas D y detección.** Configuración efectiva de solo lectura con `sshd -T -C`, `SKIP` con motivo en equipos sin shell Linux u OpenSSH, y detección de modelo y firmware según el perfil de dispositivo.

La 3b usa el login de la 3a, así que va después.

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
