import pytest
from httpx import ASGITransport, AsyncClient

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.web.app import create_app


def _app(allow):
    return create_app(Config(
        allow_networks=allow, policies_dir="config/policies", profiles_dir="config/profiles",
    ))


@pytest.mark.asyncio
async def test_tests_catalog_and_scan_and_export(ssh_server):
    host, port = ssh_server
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/v1/tests")
        assert r.status_code == 200 and any(t["id"] == "negotiation" for t in r.json())
        r = await c.post("/api/v1/scans", json={
            "target_host": host, "port": port,
            "tests": ["connectivity", "negotiation"], "policy": "opengear-base",
        })
        assert r.status_code == 200
        sid = r.json()["scan_id"]
        r = await c.get(f"/api/v1/scans/{sid}/export?format=csv")
        assert r.status_code == 200 and "negotiation" in r.text


@pytest.mark.asyncio
async def test_scan_denied_outside_allowlist():
    app = _app(["10.0.0.0/24"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={
            "target_host": "192.168.1.1", "tests": ["connectivity"], "policy": "opengear-base",
        })
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_compare_rejects_invalid_json():
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/compare", json={"a": {"bad": 1}, "b": {"bad": 2}})
        assert r.status_code == 422
