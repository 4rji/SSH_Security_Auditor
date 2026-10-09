import pytest
from httpx import ASGITransport, AsyncClient

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.web.app import create_app


def _app(allow, custom_dir=""):
    return create_app(Config(
        allow_networks=allow, policies_dir="config/policies", profiles_dir="config/profiles",
        custom_dir=str(custom_dir),
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
            "tests": ["connectivity", "negotiation"], "policy": "base", "run_by": "Ana",
        })
        assert r.status_code == 200
        assert r.json()["run_by"] == "Ana"
        sid = r.json()["scan_id"]
        r = await c.get(f"/api/v1/scans/{sid}/export?format=csv")
        assert r.status_code == 200 and "negotiation" in r.text


@pytest.mark.asyncio
async def test_scan_denied_outside_allowlist():
    app = _app(["10.0.0.0/24"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={
            "target_host": "192.168.1.1", "tests": ["connectivity"], "policy": "base",
        })
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_compare_rejects_invalid_json():
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/compare", json={"a": {"bad": 1}, "b": {"bad": 2}})
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_profiles_and_policies_shared_lifecycle(tmp_path):
    app = _app(["127.0.0.0/8"], custom_dir=tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/v1/policies")
        assert [p["id"] for p in r.json()] == ["base"]
        r = await c.get("/api/v1/policies/example.yaml")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        r = await c.get("/api/v1/profiles/generic/yaml")
        assert r.status_code == 200 and "id: generic" in r.text
        r = await c.get("/api/v1/profiles/nope/yaml")
        assert r.status_code == 404

        # A profile can't point at a policy that doesn't exist.
        prof = "id: lab-router\nname: Lab router\npolicy: strict\n"
        r = await c.post("/api/v1/profiles", json={"yaml": prof, "uploaded_by": "Ana"})
        assert r.status_code == 422 and "strict" in r.json()["detail"]

        r = await c.post("/api/v1/policies", json={"yaml": "id: strict\n", "uploaded_by": "Ana"})
        assert r.status_code == 201
        pol_token = r.json()["owner_token"]
        r = await c.post("/api/v1/policies", json={"yaml": "id: strict\n", "uploaded_by": "Bo"})
        assert r.status_code == 409
        r = await c.post("/api/v1/profiles", json={"yaml": prof, "uploaded_by": "Ana"})
        assert r.status_code == 201
        prof_token = r.json()["owner_token"]

        listed = {p["id"]: p for p in (await c.get("/api/v1/profiles")).json()}
        assert listed["lab-router"]["policy"] == "strict"
        assert listed["lab-router"]["uploaded_by"] == "Ana"

        # In use by a profile → can't delete; wrong token → forbidden; built-in → forbidden.
        r = await c.delete("/api/v1/policies/strict", headers={"X-Owner-Token": pol_token})
        assert r.status_code == 409
        r = await c.delete("/api/v1/profiles/lab-router", headers={"X-Owner-Token": "x"})
        assert r.status_code == 403
        r = await c.delete("/api/v1/profiles/generic", headers={"X-Owner-Token": prof_token})
        assert r.status_code == 403
        r = await c.delete("/api/v1/profiles/lab-router", headers={"X-Owner-Token": prof_token})
        assert r.status_code == 204
        r = await c.delete("/api/v1/policies/strict", headers={"X-Owner-Token": pol_token})
        assert r.status_code == 204
        assert [p["id"] for p in (await c.get("/api/v1/policies")).json()] == ["base"]


@pytest.mark.asyncio
async def test_scan_with_unknown_policy_or_bad_id_is_rejected():
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={
            "target_host": "127.0.0.1", "tests": ["connectivity"], "policy": "missing",
        })
        assert r.status_code == 404
        r = await c.post("/api/v1/scans", json={
            "target_host": "127.0.0.1", "tests": ["connectivity"], "policy": "../../etc/x",
        })
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_two_devices_scanned_and_compared_by_id(ssh_server):
    import asyncssh

    class _Other(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

    other = await asyncssh.create_server(
        _Other, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
        server_version="OtherServer_2.0",
        encryption_algs=["aes256-gcm@openssh.com", "aes128-ctr"],
    )
    (host_a, port_a), port_b = ssh_server, other.sockets[0].getsockname()[1]
    try:
        app = _app(["127.0.0.0/8"])
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            ids = []
            for port in (port_a, port_b):
                r = await c.post("/api/v1/scans", json={
                    "target_host": host_a, "port": port,
                    "tests": ["connectivity", "negotiation"], "policy": "base",
                })
                assert r.status_code == 200
                ids.append(r.json()["scan_id"])
            r = await c.post("/api/v1/compare", json={"a_id": ids[0], "b_id": ids[1]})
            assert r.status_code == 200
            res = r.json()
    finally:
        other.close()
        await other.wait_closed()

    assert (res["meta"]["a"]["port"], res["meta"]["b"]["port"]) == (port_a, port_b)
    neg = {f["field"]: f for f in res["evidence_diff"]["negotiation"]["fields"]}
    assert neg["software"]["changed"] and neg["software"]["after"].endswith("OtherServer_2.0")
    assert neg["enc_s2c"]["after"] == ["aes256-gcm@openssh.com", "aes128-ctr"]
    fp = {i["key"]: i["change"] for i in neg["host_key_fingerprints"]["items"]}
    assert fp["ssh-ed25519"] == "Changed"


@pytest.mark.asyncio
async def test_rest_enforces_the_same_limits():
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={
            "target_host": "127.0.0.1", "tests": ["connectivity"], "concurrency": 99,
        })
        assert r.status_code == 422 and "exceeds" in r.json()["detail"]
        r = await c.post("/api/v1/scans", json={"target_host": "127.0.0.1", "tests": ["bogus"]})
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_request_fields_get_a_readable_message():
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json={
            "target_host": "127.0.0.1", "port": 70000, "tests": ["connectivity"],
        })
        assert r.status_code == 422
        detail = r.json()["detail"]
        # The web shows `detail` as is; a list would read "[object Object]".
        assert isinstance(detail, str) and "port" in detail and "65535" in detail
