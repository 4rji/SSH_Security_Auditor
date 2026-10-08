from __future__ import annotations

from ssh_auditor.models import ScanResult, Status

_RANK = {
    Status.FAIL: 0, Status.ERROR: 0, Status.WARN: 1,
    Status.INFO: 2, Status.SKIP: 2, Status.PASS: 3,
}


def _change(sa: Status, sb: Status) -> str:
    ra, rb = _RANK[sa], _RANK[sb]
    if rb > ra:
        return "Mejoró"
    if rb < ra:
        return "Empeoró"
    return "Igual"


def _list_diff(la, lb) -> dict:
    sa, sb = set(la or []), set(lb or [])
    return {"added": sorted(sb - sa), "removed": sorted(sa - sb)}


def compare(a: ScanResult, b: ScanResult) -> dict:
    ra = {r.test_id: r for r in a.results}
    rb = {r.test_id: r for r in b.results}

    tests = []
    for tid in sorted(set(ra) | set(rb)):
        if tid in ra and tid in rb:
            sa, sb = ra[tid].status, rb[tid].status
            change = _change(sa, sb)
        elif tid in rb:
            change, sa, sb = "Nueva", None, rb[tid].status
        else:
            change, sa, sb = "Desaparecida", ra[tid].status, None
        tests.append({
            "test_id": tid, "change": change,
            "status_a": sa.value if sa else None,
            "status_b": sb.value if sb else None,
        })

    evidence_diff = {}
    for tid in set(ra) & set(rb):
        da, db = ra[tid].evidence.data, rb[tid].evidence.data
        entry: dict = {}
        for field in ("kex", "server_host_key", "enc_s2c", "mac_s2c"):
            if field in da or field in db:
                entry[field] = _list_diff(da.get(field), db.get(field))
        fa = da.get("host_key_fingerprints") or {}
        fb = db.get("host_key_fingerprints") or {}
        entry["host_key_changed"] = bool(fa) and bool(fb) and fa != fb
        evidence_diff[tid] = entry

    warnings = []
    if a.tool_version != b.tool_version:
        warnings.append(f"Versión de herramienta distinta: {a.tool_version} vs {b.tool_version}")
    for tid in set(ra) & set(rb):
        if ra[tid].test_version != rb[tid].test_version:
            warnings.append(
                f"Versión del plugin '{tid}' distinta: "
                f"{ra[tid].test_version} vs {rb[tid].test_version}"
            )

    return {"tests": tests, "evidence_diff": evidence_diff, "warnings": warnings}
