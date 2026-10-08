from datetime import datetime, timezone

from ssh_auditor.compare import compare
from ssh_auditor.models import Evidence, ScanResult, Status, TestResult


def _sr(results, tool="0.1.0"):
    return ScanResult(
        scan_id="x", target_host="h", port=22, profile="p", policy_name="base",
        started_at=datetime.now(timezone.utc), finished_at=None, status="done",
        results=results, tool_version=tool,
    )


def _tr(tid, status, ev=None):
    return TestResult(
        test_id=tid, test_version="1", category="B", status=status,
        findings=[], evidence=Evidence(data=ev or {}), duration_ms=1, impact="none",
    )


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
    assert "y" in diff["kex"]["added"]
    assert any("versión" in w.lower() or "version" in w.lower() for w in res["warnings"])
