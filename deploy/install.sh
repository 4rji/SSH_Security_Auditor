#!/usr/bin/env bash
# Instalador para Debian 13. Ejecutar como root: sudo deploy/install.sh
# No ejecuta git ni arranca nada automáticamente; al final indica los pasos manuales.
set -euo pipefail

APP_DIR=/opt/ssh-auditor
CFG_DIR=/etc/ssh-auditor
SVC_USER=sshauditor
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta como root (sudo)." >&2
  exit 1
fi

echo ">> Dependencias del sistema"
apt-get update
apt-get install -y python3 python3-venv python3-pip

echo ">> Usuario de servicio"
if ! id "$SVC_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

echo ">> Copia de la aplicación a $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/ssh_auditor" "$SRC_DIR/config" "$SRC_DIR/pyproject.toml" "$APP_DIR/"
[[ -f "$SRC_DIR/requirements.txt" ]] && cp "$SRC_DIR/requirements.txt" "$APP_DIR/"

echo ">> Entorno virtual y dependencias"
python3 -m venv "$APP_DIR/.venv"
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  "$APP_DIR/.venv/bin/pip" install --require-hashes -r "$APP_DIR/requirements.txt" || \
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
else
  "$APP_DIR/.venv/bin/pip" install "$APP_DIR"
fi

echo ">> Configuración en $CFG_DIR"
mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_DIR/config.yaml" ]]; then
  cp "$SRC_DIR/config/config.example.yaml" "$CFG_DIR/config.yaml"
  echo "   Creado $CFG_DIR/config.yaml — AJUSTA allow_networks antes de usar."
fi

chown -R "$SVC_USER:$SVC_USER" "$APP_DIR" "$CFG_DIR"

echo ">> Servicio systemd"
cp "$SRC_DIR/deploy/ssh-auditor.service" /etc/systemd/system/ssh-auditor.service
systemctl daemon-reload

cat <<EOF

Instalación completada.

Pasos manuales:
  1. Edita $CFG_DIR/config.yaml y pon las redes autorizadas en allow_networks.
  2. systemctl enable --now ssh-auditor
  3. Abre http://<este-servidor>:7284/

EOF
