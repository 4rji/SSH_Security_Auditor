# SSH Security Auditor

Herramienta interna para auditar la postura SSH de equipos Opengear, routers y otros
dispositivos de red: negociación (algoritmos, host keys, Terrapin, KEX post-cuántico),
y —en fases siguientes— autenticación, configuración efectiva de `sshd`, yescrypt y
concurrencia. Sin estado en servidor: los resultados viven en el navegador y en las
exportaciones. Accesible desde la web y desde Claude (MCP, Fase 2).

Solo para uso en **red interna** y contra **equipos autorizados** (allowlist obligatoria).

## Estado

Fase 1 implementada: motor de plugins, pruebas de conectividad y negociación (sin login),
API, web de 4 pasos con progreso en tiempo real, exportación JSON/HTML/CSV y comparación
de ejecuciones. Plan completo en `docs/superpowers/plans/` e `instrucciones.md`.

## Desarrollo

```bash
python3 -m venv .venv            # en Debian 13: puede requerir get-pip (ver más abajo)
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q              # toda la suite
SSH_AUDITOR_CONFIG=config/config.example.yaml .venv/bin/python -m ssh_auditor
```

Luego abre `http://localhost:7284/`. Ajusta `allow_networks` en el YAML antes de escanear.

> Si `python3 -m venv` crea el entorno sin `pip` (Debian minimal), arráncalo con:
> `python3 -m venv --without-pip .venv && curl -fsSL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python`

## Despliegue en Debian 13

```bash
sudo deploy/install.sh
sudo nano /etc/ssh-auditor/config.yaml   # poner allow_networks
sudo systemctl enable --now ssh-auditor
```

## Seguridad

- Allowlist de redes destino obligatoria (vacía = rechaza todo).
- El servidor no guarda credenciales ni resultados en disco.
- Caché de resultados solo en RAM, con TTL.
- Solo red interna, sin token.

## Licencia

Interno.
