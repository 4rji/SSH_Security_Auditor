from datetime import datetime, timezone

from ssh_auditor.models import Evidence, Finding, ScanResult, Status, TestResult


def test_scan_result_summary_counts_by_status():
    def tr(status):
        return TestResult(
            test_id="t", test_version="1", category="B", status=status,
            findings=[], evidence=Evidence(data={}), duration_ms=1, impact="none",
        )

    sr = ScanResult(
        scan_id="s1", target_host="10.0.0.5", port=22, profile="generico",
        policy_name="base", started_at=datetime.now(timezone.utc),
        finished_at=None, status="running",
        results=[tr(Status.PASS), tr(Status.PASS), tr(Status.FAIL)],
        tool_version="0.1.0",
    )
    assert sr.schema_version == "1"
    assert sr.summary()[Status.PASS] == 2
    assert sr.summary()[Status.FAIL] == 1


def test_finding_defaults_source_network():
    f = Finding(id="f1", status=Status.PASS, summary="ok")
    assert f.source == "network"
    assert f.recommendation == ""
