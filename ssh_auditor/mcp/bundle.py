"""Downloads for the "Connect with Claude" page: a .mcp.json for Claude Code and a .mcpb
bundle for Claude Desktop (a zip holding a manifest and a local stdio→HTTP bridge)."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

BRIDGE = Path(__file__).parent / "bridge" / "index.js"
SERVER_NAME = "ssh-auditor"


def mcp_json(mcp_url: str) -> dict:
    return {"mcpServers": {SERVER_NAME: {"type": "http", "url": mcp_url}}}


def manifest(mcp_url: str, version: str, tools: list[dict]) -> dict:
    return {
        "manifest_version": "0.3",
        "name": SERVER_NAME,
        "display_name": "SSH Security Auditor",
        "version": version,
        "description": "Audit the SSH posture of internal network devices from Claude.",
        "long_description": (
            "Connects Claude Desktop to the team's SSH Security Auditor. Claude's remote "
            "connectors run from Anthropic's cloud and can't reach an internal server, so "
            "this extension runs a small local bridge that forwards MCP messages to it."
        ),
        "author": {"name": "SSH Security Auditor"},
        "server": {
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {
                "command": "node",
                "args": ["${__dirname}/server/index.js"],
                "env": {"SSH_AUDITOR_URL": "${user_config.server_url}"},
            },
        },
        "user_config": {
            "server_url": {
                "type": "string",
                "title": "Server URL",
                "description": "The auditor's MCP endpoint on the internal network.",
                "default": mcp_url,
                "required": True,
            },
        },
        "tools": tools,
        "compatibility": {
            "platforms": ["darwin", "win32", "linux"],
            "runtimes": {"node": ">=18.0.0"},
        },
    }


def build_mcpb(mcp_url: str, version: str, tools: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest(mcp_url, version, tools), indent=2))
        z.writestr("server/index.js", BRIDGE.read_text())
    return buf.getvalue()
