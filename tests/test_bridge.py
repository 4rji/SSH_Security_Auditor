import asyncio
import json
import os
import shutil
import socket

import pytest

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.mcp.bundle import BRIDGE
from ssh_auditor.web.app import create_app

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}}


async def _bridge(url: str):
    proc = await asyncio.create_subprocess_exec(
        "node", str(BRIDGE), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "SSH_AUDITOR_URL": url},
    )

    async def ask(msg: dict):
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        await proc.stdin.drain()
        if "id" not in msg:
            return None
        return json.loads(await asyncio.wait_for(proc.stdout.readline(), 15))

    return proc, ask


async def _close(proc):
    proc.stdin.close()
    await asyncio.wait_for(proc.wait(), 10)


@pytest.mark.asyncio
async def test_bridge_relays_legacy_and_modern_messages(live_app):
    base = await live_app(create_app(Config(
        allow_networks=["127.0.0.0/8"], policies_dir="config/policies",
        profiles_dir="config/profiles", custom_dir="")))
    proc, ask = await _bridge(f"{base}/mcp")
    try:
        init = await ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}})
        assert init["result"]["serverInfo"]["name"] == "ssh-auditor", init
        await ask({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = await ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert "start_scan" in {t["name"] for t in tools["result"]["tools"]}
        call = await ask({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "list_tests", "arguments": {}}})
        assert call["id"] == 3 and not call["result"].get("isError"), call
        modern = await ask({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "list_tests", "arguments": {}, "_meta": META}})
        assert modern["id"] == 4 and "result" in modern, modern
    finally:
        await _close(proc)


@pytest.mark.asyncio
async def test_bridge_reports_an_unreachable_server():
    with socket.socket() as s:  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc, ask = await _bridge(f"http://127.0.0.1:{port}/mcp")
    try:
        r = await ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r["id"] == 1 and "Can't reach" in r["error"]["message"]
    finally:
        await _close(proc)


@pytest.mark.asyncio
async def test_bridge_reports_a_wrong_url_path(live_app):
    # The likeliest typo when editing the URL: leaving out /mcp, or a trailing slash.
    base = await live_app(create_app(Config(
        allow_networks=["127.0.0.0/8"], policies_dir="config/policies",
        profiles_dir="config/profiles", custom_dir="")))
    for url in (base, f"{base}/mcp/"):
        proc, ask = await _bridge(url)
        try:
            r = await ask({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
            assert r.get("id") == 7 and "HTTP 405" in r["error"]["message"], (url, r)
        finally:
            await _close(proc)
