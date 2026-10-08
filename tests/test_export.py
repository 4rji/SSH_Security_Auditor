from datetime import datetime, timezone

import pytest

from ssh_auditor.export import from_json, to_csv, to_html, to_json
from ssh_auditor.models import Evidence, Finding, ScanResult, Status, TestResult


def _sr():
    tr = TestResult(
        test_id="negotiation", test_version="1", category="B", status=Status.PASS,
        findings=[Finding(id="terrapin", status=Status.PASS, summary="ok")],
        evidence=Evidence(data={"kex": ["x"]}), duration_ms=5, impact="none",
    )
    return ScanResult(
        scan_id="s1", target_host="10.0.0.5", port=22, profile="p", policy_name="base",
        started_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc),
        status="done", results=[tr], tool_version="0.1.0",
    )


def test_json_roundtrip():
    sr = _sr()
    back = from_json(to_json(sr))
    assert back.scan_id == "s1"
    assert back.results[0].evidence.data["kex"] == ["x"]


def test_from_json_rejects_wrong_schema():
    bad = to_json(_sr()).replace('"schema_version":"1"', '"schema_version":"9"')
    with pytest.raises(ValueError):
        from_json(bad)


def test_csv_and_html_contain_test():
    sr = _sr()
    assert "negotiation" in to_csv(sr)
    html = to_html(sr)
    assert "<html" in html.lower() and "negotiation" in html
