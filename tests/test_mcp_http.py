import httpx
import pytest
from mcp import Client

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.web.app import create_app

TOOLS = {"list_tests", "list_profiles", "start_scan", "get_scan", "cancel_scan",
         "compare_scans"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "test", "version": "0"}}}


def _app():
    return create_app(Config(allow_networks=["127.0.0.0/8"], policies_dir="config/policies",
                             profiles_dir="config/profiles", custom_dir=""))


@pytest.mark.asyncio
async def test_claude_lists_scans_and_compares_over_http(ssh_server, live_app):
    host, port = ssh_server
    base = await live_app(_app())
    async with Client(f"{base}/mcp") as c:
        assert {t.name for t in (await c.list_tools()).tools} == TOOLS
        ids = []
        for _ in range(2):
            r = await c.call_tool("start_scan", {"target_host": host, "port": port,
                                                 "tests": ["connectivity", "negotiation"]})
            assert not r.is_error, r.content
            sid = r.structured_content["scan_id"]
            r = await c.call_tool("get_scan", {"scan_id": sid, "wait_s": 30})
            assert r.structured_content["state"] == "done"
            ids.append(sid)
        r = await c.call_tool("compare_scans", {"a_id": ids[0], "b_id": ids[1]})
        assert r.structured_content["summary"]["tests"] == {"Unchanged": 2}
    async with httpx.AsyncClient() as h:
        # A scan started from MCP is also visible through the REST API.
        assert (await h.get(f"{base}/api/v1/scans/{ids[0]}")).status_code == 200


@pytest.mark.asyncio
async def test_plain_http_initialize_with_a_real_hostname(live_app):
    base = await live_app(_app())
    async with httpx.AsyncClient() as h:
        r = await h.post(f"{base}/mcp", json=INIT, headers={
            "Accept": "application/json, text/event-stream",
            "Host": "auditor.internal:7284",
        })
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/json")
        res = r.json()["result"]
        assert res["serverInfo"]["name"] == "ssh-auditor"
        assert "Recommended flow" in res["instructions"]
        assert "mcp-session-id" not in r.headers  # stateless
        # The web is still served next to /mcp.
        assert (await h.get(f"{base}/")).status_code == 200
        assert (await h.get(f"{base}/api/v1/tests")).status_code == 200
