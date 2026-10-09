from __future__ import annotations

import json
from collections import Counter

from ssh_auditor.models import ScanResult, Status, TestResult

_RANK = {
    Status.FAIL: 0, Status.ERROR: 0, Status.WARN: 1,
    Status.INFO: 2, Status.SKIP: 2, Status.PASS: 3,
}


def _change(sa: Status, sb: Status) -> str:
    ra, rb = _RANK[sa], _RANK[sb]
    if rb > ra:
        return "Improved"
    if rb < ra:
        return "Regressed"
    return "Unchanged"


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _field_diff(field: str, va, vb) -> dict:
    """Difference of one evidence field, by shape: list, map or value. `missing` names the
    side ("a" or "b") that has no value at all: an older export, or a test that failed."""
    out = _shape_diff(field, va, vb)
    out["missing"] = ("a" if va is None and vb is not None
                      else "b" if vb is None and va is not None else None)
    return out


def _shape_diff(field: str, va, vb) -> dict:
    if isinstance(va, list) or isinstance(vb, list):
        la, lb = va or [], vb or []
        # Context evidence contains dictionaries. Compare all list items by a stable
        # JSON key while returning the original values to the UI.
        key = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
        ka, kb = [key(x) for x in la], [key(x) for x in lb]
        sa, sb = set(ka), set(kb)
        return {
            "field": field, "kind": "list", "before": la, "after": lb,
            # In the server's order: KEXINIT order is its preference.
            "added": [x for x, k in zip(lb, kb) if k not in sa],
            "removed": [x for x, k in zip(la, ka) if k not in sb],
            "reordered": sa == sb and ka != kb,
            "changed": la != lb,
        }
    if isinstance(va, dict) or isinstance(vb, dict):
        da, db = va or {}, vb or {}
        items = []
        for k in dict.fromkeys([*da, *db]):
            if k in da and k in db:
                change = "Unchanged" if da[k] == db[k] else "Changed"
            elif k in db:
                change = "New"
            else:
                change = "Removed"
            items.append({"key": k, "before": da.get(k), "after": db.get(k), "change": change})
        return {"field": field, "kind": "map", "items": items, "changed": da != db}
    out = {"field": field, "kind": "value", "before": va, "after": vb, "changed": va != vb}
    if _is_num(va) and _is_num(vb):
        out["delta"] = vb - va
    return out


def _findings(ta: TestResult | None, tb: TestResult | None) -> list[dict]:
    fa = {f.id: f for f in (ta.findings if ta else [])}
    fb = {f.id: f for f in (tb.findings if tb else [])}
    out = []
    for fid in dict.fromkeys([*fb, *fa]):
        a, b = fa.get(fid), fb.get(fid)
        if a and b:
            change = _change(a.status, b.status)
            if change == "Unchanged" and a.summary != b.summary:
                change = "Changed"
        elif b:
            change = "New"
        else:
            change = "Removed"
        out.append({
            "id": fid, "change": change,
            "status_a": a.status.value if a else None,
            "status_b": b.status.value if b else None,
            "summary_a": a.summary if a else None,
            "summary_b": b.summary if b else None,
            "recommendation": b.recommendation if b else "",
        })
    return out


def _meta(sr: ScanResult) -> dict:
    return {
        "scan_id": sr.scan_id, "target_host": sr.target_host, "port": sr.port,
        "target_name": sr.target_name, "model": sr.model, "firmware": sr.firmware,
        "tags": sr.tags,
        "profile": sr.profile, "policy_name": sr.policy_name,
        "started_at": sr.started_at.isoformat(), "tool_version": sr.tool_version,
        "run_by": sr.run_by,
    }


def compare(a: ScanResult, b: ScanResult) -> dict:
    ra = {r.test_id: r for r in a.results}
    rb = {r.test_id: r for r in b.results}

    tests = []
    for tid in sorted(set(ra) | set(rb)):
        if tid in ra and tid in rb:
            sa, sb = ra[tid].status, rb[tid].status
            change = _change(sa, sb)
        elif tid in rb:
            change, sa, sb = "New", None, rb[tid].status
        else:
            change, sa, sb = "Removed", ra[tid].status, None
        tests.append({
            "test_id": tid, "change": change,
            "status_a": sa.value if sa else None,
            "status_b": sb.value if sb else None,
            "findings": _findings(ra.get(tid), rb.get(tid)),
        })

    evidence_diff = {}
    for tid in sorted(set(ra) & set(rb)):
        da, db = ra[tid].evidence.data, rb[tid].evidence.data
        fa = da.get("host_key_fingerprints") or {}
        fb = db.get("host_key_fingerprints") or {}
        evidence_diff[tid] = {
            "fields": [_field_diff(f, da.get(f), db.get(f)) for f in dict.fromkeys([*db, *da])],
            "host_key_changed": bool(fa) and bool(fb) and fa != fb,
        }

    warnings = []
    if a.tool_version != b.tool_version:
        warnings.append(f"Different tool version: {a.tool_version} vs {b.tool_version}")
    if a.policy_name != b.policy_name:
        warnings.append(f"Different policy: {a.policy_name} vs {b.policy_name}")
    for tid in sorted(set(ra) & set(rb)):
        if ra[tid].test_version != rb[tid].test_version:
            warnings.append(
                f"Different '{tid}' plugin version: "
                f"{ra[tid].test_version} vs {rb[tid].test_version}"
            )

    summary = {
        "tests": dict(Counter(t["change"] for t in tests)),
        "findings": dict(Counter(f["change"] for t in tests for f in t["findings"])),
    }
    return {
        "meta": {"a": _meta(a), "b": _meta(b)},
        "summary": summary, "tests": tests,
        "evidence_diff": evidence_diff, "warnings": warnings,
    }
