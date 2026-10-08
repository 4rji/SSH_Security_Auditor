#!/usr/bin/env bash
# Installer for Debian 13. Run as root: sudo deploy/install.sh
# It runs no git and starts nothing; it prints the manual steps at the end.
set -euo pipefail

APP_DIR=/opt/ssh-auditor
CFG_DIR=/etc/ssh-auditor
SVC_USER=sshauditor
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

echo ">> System dependencies"
apt-get update
apt-get install -y python3 python3-venv python3-pip

echo ">> Service user"
if ! id "$SVC_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

echo ">> Copying the application to $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/ssh_auditor" "$SRC_DIR/config" "$SRC_DIR/pyproject.toml" "$APP_DIR/"
[[ -f "$SRC_DIR/requirements.txt" ]] && cp "$SRC_DIR/requirements.txt" "$APP_DIR/"

echo ">> Virtual environment and dependencies"
python3 -m venv "$APP_DIR/.venv"
if [[ -f "$APP_DIR/requirements.txt" ]]; then
  "$APP_DIR/.venv/bin/pip" install --require-hashes -r "$APP_DIR/requirements.txt" || \
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
else
  "$APP_DIR/.venv/bin/pip" install "$APP_DIR"
fi

echo ">> Configuration in $CFG_DIR"
mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_DIR/config.yaml" ]]; then
  cp "$SRC_DIR/config/config.example.yaml" "$CFG_DIR/config.yaml"
  echo "   Created $CFG_DIR/config.yaml — SET allow_networks before use."
fi

chown -R "$SVC_USER:$SVC_USER" "$APP_DIR" "$CFG_DIR"

echo ">> systemd service"
cp "$SRC_DIR/deploy/ssh-auditor.service" /etc/systemd/system/ssh-auditor.service
systemctl daemon-reload

cat <<EOF

Installation complete.

Manual steps:
  1. Edit $CFG_DIR/config.yaml and put the authorised networks in allow_networks.
  2. systemctl enable --now ssh-auditor
  3. Open http://<this-server>:7284/

Profiles and policies uploaded by engineers are kept in /var/lib/ssh-auditor.

EOF
