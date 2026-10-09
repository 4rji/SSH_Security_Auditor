import io
import json
import zipfile

import pytest
from httpx import ASGITransport, AsyncClient

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.mcp.bundle import BRIDGE, build_mcpb, mcp_json
from ssh_auditor.web.app import create_app

TOOLS = {"list_tests", "list_profiles", "start_scan", "get_scan", "cancel_scan",
         "compare_scans"}


def test_mcp_json_points_at_the_endpoint():
    assert mcp_json("http://a:7284/mcp") == {
        "mcpServers": {"ssh-auditor": {"type": "http", "url": "http://a:7284/mcp"}}}


def test_mcpb_is_a_zip_with_manifest_and_bridge():
    data = build_mcpb("http://a:7284/mcp", "0.1.0", [{"name": "list_tests", "description": "x"}])
    z = zipfile.ZipFile(io.BytesIO(data))
    assert set(z.namelist()) == {"manifest.json", "server/index.js"}
    m = json.loads(z.read("manifest.json"))
    assert m["manifest_version"] == "0.3" and m["version"] == "0.1.0"
    assert m["server"]["type"] == "node" and m["server"]["entry_point"] == "server/index.js"
    assert m["server"]["mcp_config"]["args"] == ["${__dirname}/server/index.js"]
    assert m["server"]["mcp_config"]["env"]["SSH_AUDITOR_URL"] == "${user_config.server_url}"
    assert m["user_config"]["server_url"]["default"] == "http://a:7284/mcp"
    assert z.read("server/index.js").decode() == BRIDGE.read_text()


@pytest.mark.asyncio
async def test_claude_downloads_use_the_address_the_engineer_used():
    app = create_app(Config(allow_networks=["127.0.0.0/8"], policies_dir="config/policies",
                            profiles_dir="config/profiles", custom_dir=""))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://auditor.lan:7284") as c:
        r = await c.get("/claude/mcp.json")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        assert r.json()["mcpServers"]["ssh-auditor"]["url"] == "http://auditor.lan:7284/mcp"
        r = await c.get("/claude/ssh-auditor.mcpb")
        assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
        m = json.loads(zipfile.ZipFile(io.BytesIO(r.content)).read("manifest.json"))
        assert m["user_config"]["server_url"]["default"] == "http://auditor.lan:7284/mcp"
        assert {t["name"] for t in m["tools"]} == TOOLS
        r = await c.get("/claude")
        assert r.status_code == 307 and r.headers["location"] == "/claude.html"
