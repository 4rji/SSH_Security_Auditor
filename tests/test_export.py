import json
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


def _sr_at(run_by=""):
    sr = _sr()
    return sr.model_copy(update={
        "run_by": run_by,
        "started_at": datetime(2026, 10, 8, 14, 30, 5, tzinfo=timezone.utc),
        "finished_at": datetime(2026, 10, 8, 14, 30, 9, tzinfo=timezone.utc),
    })


def test_exports_show_who_and_when():
    sr = _sr_at("Ana <ops>")
    html = to_html(sr)
    assert "2026-10-08 14:30:05 UTC · Run by Ana &lt;ops&gt; · Profile p · Policy base" in html
    assert "14:30:09" not in html and "Exported" not in html and "<table class='meta'" not in html
    rows = to_csv(sr).splitlines()
    assert rows[0].endswith("target,run_by,started_at")
    assert rows[1].endswith("10.0.0.5:22,Ana <ops>,2026-10-08 14:30:05 UTC")
    assert from_json(to_json(sr)).run_by == "Ana <ops>"


def test_html_without_name_omits_run_by_and_is_dark_with_toggle():
    html = to_html(_sr_at())
    assert "Run by" not in html
    assert "data-theme='dark'" in html and "button class='theme'" in html
    assert ":root[data-theme=light]" in html and "@media print" in html


def test_old_exports_without_run_by_still_import():
    raw = json.loads(to_json(_sr()))
    raw.pop("run_by")
    assert from_json(json.dumps(raw)).run_by == ""
