from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

from ssh_auditor.models import ScanResult

SCHEMA_VERSION = "1"


def to_json(sr: ScanResult) -> str:
    return sr.model_dump_json()


def from_json(text: str) -> ScanResult:
    raw = json.loads(text)
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unsupported schema_version: {raw.get('schema_version')!r}")
    return ScanResult.model_validate(raw)


def _utc(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def to_csv(sr: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["test_id", "category", "status", "summary", "target", "target_name",
                "model", "firmware", "tags", "run_by", "started_at"])
    target = f"{sr.target_host}:{sr.port}"
    for r in sr.results:
        summary = "; ".join(f.summary for f in r.findings) or r.status.value
        w.writerow([r.test_id, r.category, r.status.value, summary, target, sr.target_name,
                    sr.model, sr.firmware, ", ".join(sr.tags), sr.run_by,
                    _utc(sr.started_at)])
    return buf.getvalue()


# Dark by default; the button switches to light, and printing always uses light.
_CSS = """
:root{color-scheme:dark;--fg:#e6edf3;--mut:#9198a1;--bd:#30363d;--bg:#0d1117;--pan:#161b22;
--pass:#3fb950;--warn:#d29922;--fail:#f85149;--info:#58a6ff;--skip:#9198a1}
:root[data-theme=light]{color-scheme:light;--fg:#1f2328;--mut:#59636e;--bd:#d0d7de;--bg:#ffffff;
--pan:#f6f8fa;--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;--info:#0969da;--skip:#59636e}
@media print{:root,:root[data-theme=light]{color-scheme:light;--fg:#1f2328;--mut:#59636e;
--bd:#d0d7de;--bg:#ffffff;--pan:#f6f8fa;--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;
--info:#0969da;--skip:#59636e}.theme{display:none}}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:2rem;background:var(--bg);
color:var(--fg);line-height:1.5}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap}
h1{margin:0 0 .25rem;font-size:1.6rem}
table{border-collapse:collapse;width:100%;margin-top:1.25rem}
th,td{border:1px solid var(--bd);padding:.45rem .65rem;text-align:left;vertical-align:top;
overflow-wrap:break-word}
th{background:var(--pan)}
.ref{color:var(--mut);font-size:.9rem;margin-top:.35rem}
.st{font-weight:700;white-space:nowrap}
.PASS{color:var(--pass)}.WARN{color:var(--warn)}.FAIL{color:var(--fail)}
.ERROR{color:var(--fail)}.INFO{color:var(--info)}.SKIP{color:var(--skip)}
.muted{color:var(--mut)}
.rec{color:var(--mut);margin-top:.15rem}
button.theme{background:var(--pan);color:var(--fg);border:1px solid var(--bd);border-radius:6px;
padding:.4rem .8rem;font-size:1rem;cursor:pointer}
"""

_JS = """
(function(){var r=document.documentElement,b=document.querySelector("button.theme");
function label(){b.textContent=r.dataset.theme==="light"?"Dark mode":"Light mode";}
b.addEventListener("click",function(){r.dataset.theme=r.dataset.theme==="light"?"dark":"light";label();});
label();})();
"""


def to_html(sr: ScanResult) -> str:
    e = html.escape
    rows = []
    for r in sr.results:
        for f in r.findings:
            rec = f"<div class='rec'>{e(f.recommendation)}</div>" if f.recommendation else ""
            rows.append(
                f"<tr><td>{e(r.category)}</td><td>{e(r.test_id)}</td>"
                f"<td class='st {e(f.status.value)}'>{e(f.status.value)}</td>"
                f"<td>{e(f.summary)}{rec}</td></tr>"
            )
    summary = " · ".join(f"{k.value}: {v}" for k, v in sr.summary().items())
    # One small reference line: when the scan started, who ran it, and with what.
    ref = [_utc(sr.started_at)]
    if sr.run_by:
        ref.append(f"Run by {sr.run_by}")
    if sr.target_name:
        ref.append(f"Device {sr.target_name}")
    if sr.model:
        ref.append(f"Model {sr.model}")
    if sr.firmware:
        ref.append(f"Firmware {sr.firmware}")
    ref += [f"Profile {sr.profile}", f"Policy {sr.policy_name}",
            f"Tool {sr.tool_version}", f"Scan {sr.scan_id}"]
    return (
        "<!doctype html><html lang='en' data-theme='dark'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>SSH audit — {e(sr.target_host)}:{sr.port}</title>"
        f"<style>{_CSS}</style></head><body>"
        "<header><div>"
        f"<h1>SSH audit · {e(sr.target_host)}:{sr.port}</h1>"
        f"<div class='muted'><strong>Summary:</strong> {e(summary)}</div>"
        f"<div class='ref'>{e(' · '.join(ref))}</div>"
        "</div><button class='theme' type='button'>Light mode</button></header>"
        "<table><thead><tr><th>Category</th><th>Test</th><th>Status</th><th>Result</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        f"<script>{_JS}</script></body></html>"
    )
