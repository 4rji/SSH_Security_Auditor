from datetime import datetime, timezone

from ssh_auditor.compare import compare
from ssh_auditor.models import Evidence, Finding, ScanResult, Status, TestResult


def _sr(results, tool="0.1.0"):
    return ScanResult(
        scan_id="x", target_host="h", port=22, profile="p", policy_name="base",
        started_at=datetime.now(timezone.utc), finished_at=None, status="done",
        results=results, tool_version=tool,
    )


def _tr(tid, status, ev=None, findings=None):
    return TestResult(
        test_id=tid, test_version="1", category="B", status=status,
        findings=findings or [], evidence=Evidence(data=ev or {}), duration_ms=1, impact="none",
    )


def _f(fid, status, summary):
    return Finding(id=fid, status=status, summary=summary)


def _field(diff, name):
    return next(f for f in diff["fields"] if f["field"] == name)


def test_compare_detects_improvement_and_new():
    a = _sr([_tr("negotiation", Status.FAIL)])
    b = _sr([_tr("negotiation", Status.PASS), _tr("connectivity", Status.PASS)])
    res = compare(a, b)
    by = {t["test_id"]: t for t in res["tests"]}
    assert by["negotiation"]["change"] == "Mejoró"
    assert by["connectivity"]["change"] == "Nueva"


def test_compare_evidence_hostkey_change_and_version_warning():
    a = _sr([_tr("negotiation", Status.PASS,
                 {"host_key_fingerprints": {"ssh-ed25519": "SHA256:AAA"}, "kex": ["x"]})],
            tool="0.1.0")
    b = _sr([_tr("negotiation", Status.PASS,
                 {"host_key_fingerprints": {"ssh-ed25519": "SHA256:BBB"}, "kex": ["x", "y"]})],
            tool="0.2.0")
    res = compare(a, b)
    diff = res["evidence_diff"]["negotiation"]
    assert diff["host_key_changed"] is True
    assert "y" in _field(diff, "kex")["added"]
    assert any("versión" in w.lower() or "version" in w.lower() for w in res["warnings"])


def test_compare_findings_matched_by_id():
    a = _sr([_tr("negotiation", Status.FAIL, findings=[
        _f("terrapin", Status.FAIL, "Vulnerable a Terrapin (CVE-2023-48795)"),
        _f("hostkey:ssh-rsa", Status.INFO, "ssh-rsa SHA256:AAA"),
        _f("kex-prohibido:diffie-hellman-group1-sha1", Status.FAIL, "prohibido"),
    ])])
    b = _sr([_tr("negotiation", Status.WARN, findings=[
        _f("terrapin", Status.PASS, "No vulnerable a Terrapin"),
        _f("hostkey:ssh-rsa", Status.INFO, "ssh-rsa SHA256:BBB"),
        _f("pq-kex", Status.WARN, "Sin intercambio de claves post-cuántico"),
    ])])
    res = compare(a, b)
    fs = {f["id"]: f for f in res["tests"][0]["findings"]}
    assert fs["terrapin"]["change"] == "Mejoró"
    assert fs["terrapin"]["summary_a"].startswith("Vulnerable")
    assert fs["hostkey:ssh-rsa"]["change"] == "Cambió"
    assert fs["pq-kex"]["change"] == "Nuevo"
    assert fs["kex-prohibido:diffie-hellman-group1-sha1"]["change"] == "Desaparecido"
    assert res["summary"]["findings"]["Mejoró"] == 1
    assert res["summary"]["tests"] == {"Mejoró": 1}


def test_compare_evidence_field_kinds():
    a = _sr([_tr("connectivity", Status.PASS, {"connect_ms": 10, "tcp_open": True,
                                                "banner": "SSH-2.0-OpenSSH_9.2"}),
             _tr("negotiation", Status.PASS, {"kex": ["a", "b"], "enc_s2c": ["x", "y"],
                                               "host_key_fingerprints": {"ssh-ed25519": "F1"}})])
    b = _sr([_tr("connectivity", Status.PASS, {"connect_ms": 25, "tcp_open": True,
                                                "banner": "SSH-2.0-OpenSSH_9.9"}),
             _tr("negotiation", Status.PASS, {"kex": ["b", "a"], "enc_s2c": ["x", "z"],
                                               "host_key_fingerprints": {"ssh-ed25519": "F1",
                                                                         "rsa-sha2-512": "F2"}})])
    ev = compare(a, b)["evidence_diff"]
    ms = _field(ev["connectivity"], "connect_ms")
    assert ms["kind"] == "value" and ms["delta"] == 15 and ms["changed"]
    assert _field(ev["connectivity"], "banner")["changed"]
    assert not _field(ev["connectivity"], "tcp_open")["changed"]
    assert "delta" not in _field(ev["connectivity"], "tcp_open")
    kex = _field(ev["negotiation"], "kex")
    assert kex["reordered"] and not kex["added"] and not kex["removed"]
    enc = _field(ev["negotiation"], "enc_s2c")
    assert enc["added"] == ["z"] and enc["removed"] == ["y"]
    fps = {i["key"]: i["change"] for i in _field(ev["negotiation"], "host_key_fingerprints")["items"]}
    assert fps == {"ssh-ed25519": "Igual", "rsa-sha2-512": "Nueva"}
    assert ev["negotiation"]["host_key_changed"] is True
