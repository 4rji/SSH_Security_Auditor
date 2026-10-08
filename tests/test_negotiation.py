import asyncssh
import pytest

from ssh_auditor.store import Store

from ssh_auditor.models import Evidence, Status
from ssh_auditor.plugins.base import Context
from ssh_auditor.plugins.negotiation import NegotiationPlugin


@pytest.mark.asyncio
async def test_negotiation_reads_algorithms(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    assert len(ev.data["kex"]) > 0
    assert len(ev.data["server_host_key"]) > 0
    assert any(fp.startswith("SHA256:") for fp in ev.data["host_key_fingerprints"].values())
    assert "terrapin" in ev.data and "pq_kex" in ev.data
    assert ev.data["software"].endswith("TestServer_1.0")
    assert ev.data["negotiated"]["kex"] in ev.data["kex"]
    assert ev.data["auth_methods"] == []
    ids = {f.id for f in p.evaluate(ev, {})}
    assert {"version", "negotiated:kex", "strict-kex", "aead", "fips", "auth-methods"} <= ids


@pytest.mark.asyncio
async def test_negotiation_policy_flags_prohibited(ssh_server):
    host, port = ssh_server
    p = NegotiationPlugin()
    ev = await p.collect(Context(host=host, port=port, policy={}, params={}, emit=lambda m: None))
    policy = {"kex": {"forbidden": [ev.data["kex"][0]]}}
    findings = p.evaluate(ev, policy)
    assert any(f.status == Status.FAIL for f in findings)


class _PwServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True


@pytest.mark.asyncio
async def test_negotiation_reads_auth_methods():
    server = await asyncssh.create_server(
        _PwServer, "127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")],
    )
    host, port = server.sockets[0].getsockname()[:2]
    try:
        p = NegotiationPlugin()
        ev = await p.collect(Context(host=host, port=port, policy={}, params={},
                                     emit=lambda m: None))
    finally:
        server.close()
        await server.wait_closed()
    assert "password" in ev.data["auth_methods"]
    f = next(f for f in p.evaluate(ev, {}) if f.id == "auth-methods")
    assert f.status == Status.INFO and "password" in f.summary


def _legacy_evidence(**over):
    data = {
        "banner": "SSH-2.0-OpenSSH_7.4", "software": "OpenSSH_7.4",
        "negotiated": {"kex": "curve25519-sha256", "host_key": "rsa-sha2-512",
                       "cipher": "aes128-ctr", "mac": "hmac-sha2-256"},
        "kex": ["curve25519-sha256", "diffie-hellman-group14-sha1"],
        "server_host_key": ["rsa-sha2-512", "ssh-rsa"],
        "enc_s2c": ["aes128-ctr", "aes128-cbc"],
        "mac_s2c": ["hmac-sha2-256", "hmac-sha1"],
        "comp_s2c": ["none"], "strict_kex": False, "terrapin": False,
        "pq_kex": False, "pq_kex_algs": [], "aead": [], "etm": [],
        "fips_path": {"kex": None, "host_key": "rsa-sha2-512", "cipher": "aes128-ctr",
                      "mac": "hmac-sha2-256"},
        "auth_methods": ["none"], "auth_methods_error": None,
        "host_key_fingerprints": {"rsa-sha2-512": "SHA256:AAA"},
    }
    data.update(over)
    return Evidence(data=data)


def test_evaluate_legacy_server_against_base_policy():
    policy = Store("policies", "config/policies", None).load("base").model_dump()
    by = {f.id: f for f in NegotiationPlugin().evaluate(_legacy_evidence(), policy)}
    for fid in ("kex-forbidden:diffie-hellman-group14-sha1", "hostkey-forbidden:ssh-rsa",
                "cipher-forbidden:aes128-cbc", "mac-forbidden:hmac-sha1"):
        assert by[fid].status == Status.FAIL
    assert "no-forbidden" not in by
    assert by["strict-kex"].status == Status.WARN
    assert by["aead"].status == Status.WARN
    assert by["etm"].status == Status.WARN
    assert by["fips"].status == Status.WARN and "KEX" in by["fips"].summary
    assert by["auth-methods"].status == Status.FAIL
    assert by["version"].summary.endswith("OpenSSH_7.4")


def test_evaluate_negotiation_failure_and_clean_policy():
    ev = _legacy_evidence(negotiated={"kex": None, "host_key": "rsa-sha2-512",
                                      "cipher": "aes128-ctr", "mac": "hmac-sha2-256"},
                          auth_methods=None, auth_methods_error="KeyExchangeFailed: x")
    by = {f.id: f for f in NegotiationPlugin().evaluate(ev, {})}
    assert by["negotiated:kex"].status == Status.FAIL
    assert by["negotiated:cipher"].status == Status.INFO
    assert by["no-forbidden"].status == Status.PASS
    assert by["auth-methods"].status == Status.WARN
