from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from ssh_auditor.config import load_config
from ssh_auditor.web.app import create_app

DEFAULT_CONFIG = "/etc/ssh-auditor/config.yaml"
FALLBACK_CONFIG = "config/config.example.yaml"


def _config_path() -> str:
    env = os.environ.get("SSH_AUDITOR_CONFIG")
    if env:
        return env
    if Path(DEFAULT_CONFIG).exists():
        return DEFAULT_CONFIG
    return FALLBACK_CONFIG


def main() -> None:
    cfg = load_config(_config_path())
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.listen_host, port=cfg.listen_port)


if __name__ == "__main__":
    main()
