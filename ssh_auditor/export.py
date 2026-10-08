from __future__ import annotations

import csv
import html
import io
import json

from ssh_auditor.models import ScanResult

SCHEMA_VERSION = "1"


def to_json(sr: ScanResult) -> str:
    return sr.model_dump_json()


def from_json(text: str) -> ScanResult:
    raw = json.loads(text)
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version no soportado: {raw.get('schema_version')!r}")
    return ScanResult.model_validate(raw)


def to_csv(sr: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["test_id", "category", "status", "summary"])
    for r in sr.results:
        summary = "; ".join(f.summary for f in r.findings) or r.status.value
        w.writerow([r.test_id, r.category, r.status.value, summary])
    return buf.getvalue()


_STATUS_COLOR = {
    "PASS": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e",
    "ERROR": "#cf222e", "INFO": "#0969da", "SKIP": "#57606a",
}


def to_html(sr: ScanResult) -> str:
    rows = []
    for r in sr.results:
        for f in r.findings:
            color = _STATUS_COLOR.get(f.status.value, "#000")
            rec = f" — {html.escape(f.recommendation)}" if f.recommendation else ""
            rows.append(
                f"<tr><td>{html.escape(r.category)}</td>"
                f"<td>{html.escape(r.test_id)}</td>"
                f"<td style='color:{color};font-weight:600'>{html.escape(f.status.value)}</td>"
                f"<td>{html.escape(f.summary)}{rec}</td></tr>"
            )
    body = "\n".join(rows)
    summary = "  ".join(f"{k.value}: {v}" for k, v in sr.summary().items())
    return (
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>SSH Auditor — {html.escape(sr.target_host)}</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:960px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;font-size:.9rem}"
        "th{background:#f6f8fa}</style></head><body>"
        f"<h1>{html.escape(sr.target_host)}:{sr.port}</h1>"
        f"<p>Perfil: {html.escape(sr.profile)} · Política: {html.escape(sr.policy_name)} · "
        f"Herramienta: {html.escape(sr.tool_version)}</p>"
        f"<p><strong>Resumen:</strong> {html.escape(summary)}</p>"
        "<table><thead><tr><th>Categoría</th><th>Prueba</th><th>Estado</th>"
        f"<th>Resumen</th></tr></thead><tbody>{body}</tbody></table></body></html>"
    )
