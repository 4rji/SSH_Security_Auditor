import json

import pytest
from httpx import ASGITransport, AsyncClient

import ssh_auditor.plugins  # noqa: F401
from ssh_auditor.config import Config
from ssh_auditor.models import Evidence, Finding, Status
from ssh_auditor.plugins.base import REGISTRY, Meta, register
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


@pytest.mark.asyncio
async def test_credentials_never_leave_rest_cache_sse_or_exports(ssh_server):
    host, port = ssh_server
    secrets = (
        "REST-PASSWORD-SECRET-7fb5d8",
        "REST-PRIVATE-KEY-SECRET-7fb5d8",
        "REST-PASSPHRASE-SECRET-7fb5d8",
        "REST-CERTIFICATE-SECRET-7fb5d8",
        "REST-KBDINT-SECRET-7fb5d8",
    )
    request = {
        "target_host": host,
        "port": port,
        "tests": ["connectivity"],
        "policy": "base",
        "credentials": {
            "method": "password",
            "username": "auditor",
            "password": secrets[0],
            "private_key": secrets[1],
            "private_key_passphrase": secrets[2],
            "certificate": secrets[3],
            "keyboard_interactive_responses": [secrets[4]],
        },
    }
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        response = await c.post("/api/v1/scans", json=request)
        assert response.status_code == 200
        assert all(secret not in response.text for secret in secrets)
        scan_id = response.json()["scan_id"]

        # This endpoint reads the already completed ScanResult from the TTL cache.
        cached = await c.get(f"/api/v1/scans/{scan_id}")
        assert cached.status_code == 200
        assert all(secret not in cached.text for secret in secrets)
        assert "credentials" not in cached.json()

        for export_format in ("json", "csv", "html"):
            exported = await c.get(
                f"/api/v1/scans/{scan_id}/export", params={"format": export_format},
            )
            assert exported.status_code == 200
            assert all(secret not in exported.text for secret in secrets)

        streamed = await c.post("/api/v1/scans/stream", json=request)
        assert streamed.status_code == 200
        assert all(secret not in streamed.text for secret in secrets)
        events = [
            json.loads(line.removeprefix("data: "))
            for line in streamed.text.splitlines()
            if line.startswith("data: ")
        ]
        assert events[-1]["type"] == "result"
        assert "credentials" not in events[-1]["result"]


@pytest.mark.asyncio
async def test_rest_validation_error_does_not_echo_a_secret():
    secret = "REST-INVALID-SECRET-8c39ad"
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        response = await c.post("/api/v1/scans", json={
            "target_host": "127.0.0.1",
            "tests": ["connectivity"],
            "credentials": {
                "method": "password",
                "username": "auditor",
                "password": secret + ("x" * 4096),
            },
        })

    assert response.status_code == 422
    assert secret not in response.text
    assert "credentials.password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_remote_or_plugin_output_is_redacted_before_events_cache_and_exports():
    marker = "REMOTE-ECHOED-PASSWORD-SECRET-f2ad91"

    class CredentialEcho:
        meta = Meta(
            id="credential_echo", version="1", category="C", name="Credential echo",
            impact="none", requires_auth=True, timeout_s=1.0,
        )

        async def collect(self, ctx):
            secret = ctx.credentials.password.get_secret_value()
            ctx.emit(f"remote progress contained {secret}")
            return Evidence(data={
                "stdout": secret,
                "remote_data": {"nested": [secret]},
            })

        def evaluate(self, evidence, _policy):
            secret = evidence.data["stdout"]
            return [Finding(
                id="credential-echo", status=Status.WARN,
                summary=f"remote summary contained {secret}",
                recommendation=f"remove {secret}",
            )]

    register(CredentialEcho())
    request = {
        "target_host": "127.0.0.1", "tests": ["credential_echo"],
        "credentials": {
            "method": "password", "username": "audit", "password": marker,
        },
    }
    app = _app(["127.0.0.0/8"])
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            response = await c.post("/api/v1/scans", json=request)
            assert response.status_code == 200
            assert marker not in response.text
            assert "[REDACTED]" in response.text
            scan_id = response.json()["scan_id"]

            cached = await c.get(f"/api/v1/scans/{scan_id}")
            assert marker not in cached.text
            for export_format in ("json", "csv", "html"):
                exported = await c.get(
                    f"/api/v1/scans/{scan_id}/export",
                    params={"format": export_format},
                )
                assert marker not in exported.text

            streamed = await c.post("/api/v1/scans/stream", json=request)
            assert streamed.status_code == 200
            assert marker not in streamed.text
            assert "[REDACTED]" in streamed.text
    finally:
        REGISTRY.pop("credential_echo", None)
