"use strict";

// Shared frontend module for both pages (the auditor and Load testing). Classic script,
// loaded before app.js / load.js, so these top-level bindings live in the global lexical
// scope both pages share. It holds the pieces that are identical on every page: the
// credential store/form, the scan streaming, the results rendering, and the comparison
// renderer. Page-specific glue (profiles, the step forms, the test catalog) stays in the
// per-page script. Scan results live only in the browser (sessionStorage), never on the
// server; credentials are persisted only after an explicit Save, keyed by host:port.

const $ = (id) => document.getElementById(id);

// Shared state: the current result and the test id→name map, written by each page's
// scan code and read by the renderers here.
let lastResult = null;
let testNames = {};
let resultsTab = "";

// localStorage can be missing or throw (private window, blocked site data).
const local = {
  get(key, fallback) {
    try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); }
    catch (_) { return fallback; }
  },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} },
};
const CREDENTIALS_KEY = "sshAuditor.credentials.v1";

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(await errorDetail(r));
  return r.json();
}

async function errorDetail(r) {
  try { return (await r.json()).detail || r.statusText; } catch (_) { return r.statusText || "HTTP " + r.status; }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// --- credentials -------------------------------------------------------------------

function credentialTargetKey(host = $("host").value, port = $("port").value) {
  const normalized = String(host || "").trim().toLowerCase().replace(/\.$/, "");
  return normalized ? `${normalized}:${parseInt(port || "22", 10)}` : "";
}

function emptyCredentialForm() {
  $("authMethod").value = "none";
  ["authUsername", "authPassword", "authPrivateKey", "authPassphrase",
   "authCertificate", "authResponses"].forEach((id) => { $(id).value = ""; });
  updateCredentialFields();
}

function credentialFromForm() {
  const method = $("authMethod").value;
  const out = { method, username: $("authUsername").value.trim() };
  if (method === "none") return out;
  if (method === "password") out.password = $("authPassword").value;
  if (method === "private_key" || method === "certificate") {
    out.private_key = $("authPrivateKey").value;
    if ($("authPassphrase").value) out.private_key_passphrase = $("authPassphrase").value;
  }
  if (method === "certificate") out.certificate = $("authCertificate").value;
  if (method === "keyboard_interactive") {
    out.keyboard_interactive_responses = $("authResponses").value.split("\n");
  }
  return out;
}

function fillCredentialForm(credential) {
  emptyCredentialForm();
  if (!credential || !credential.method) return;
  $("authMethod").value = credential.method;
  $("authUsername").value = credential.username || "";
  $("authPassword").value = credential.password || "";
  $("authPrivateKey").value = credential.private_key || "";
  $("authPassphrase").value = credential.private_key_passphrase || "";
  $("authCertificate").value = credential.certificate || "";
  $("authResponses").value = (credential.keyboard_interactive_responses || []).join("\n");
  updateCredentialFields();
}

function savedCredential(host, port) {
  return local.get(CREDENTIALS_KEY, {})[credentialTargetKey(host, port)] || null;
}

function updateCredentialFields() {
  const method = $("authMethod").value;
  document.querySelectorAll(".credential-field").forEach((el) => {
    el.hidden = !el.dataset.methods.split(" ").includes(method);
  });
  $("credentialForget").disabled = !credentialTargetKey() ||
    !savedCredential($("host").value, $("port").value);
}

function restoreCredentials() {
  const credential = savedCredential($("host").value, $("port").value);
  fillCredentialForm(credential);
  $("credentialMsg").textContent = credential
    ? "Loaded credentials saved for this host and port." : "";
}

function saveCredentials() {
  const key = credentialTargetKey();
  const credential = credentialFromForm();
  if (!key) { $("credentialMsg").textContent = "Enter the target host first."; return; }
  if (credential.method === "none" && !credential.username) {
    $("credentialMsg").textContent = "Choose an authentication method or enter a username.";
    return;
  }
  if (!credential.username) { $("credentialMsg").textContent = "Enter a username."; return; }
  const all = local.get(CREDENTIALS_KEY, {});
  all[key] = credential;
  local.set(CREDENTIALS_KEY, all);
  $("credentialMsg").textContent = `Saved in this browser for ${key}.`;
  updateCredentialFields();
}

function forgetCredentials() {
  const key = credentialTargetKey();
  const all = local.get(CREDENTIALS_KEY, {});
  if (key) delete all[key];
  local.set(CREDENTIALS_KEY, all);
  emptyCredentialForm();
  $("credentialMsg").textContent = key ? `Forgot credentials for ${key}.` : "Credentials cleared.";
}

function setupCredentials() {
  $("authMethod").addEventListener("change", updateCredentialFields);
  $("credentialSave").addEventListener("click", saveCredentials);
  $("credentialForget").addEventListener("click", forgetCredentials);
  $("host").addEventListener("change", restoreCredentials);
  $("port").addEventListener("change", restoreCredentials);
  updateCredentialFields();
}

// --- scan streaming ----------------------------------------------------------------

// Runs one scan with live progress. `log` receives each progress line; resolves with
// the final result.
async function streamScan(body, log) {
  const r = await fetch("/api/v1/scans/stream", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await errorDetail(r));
  let result = null, failure = null;
  await readSSE(r.body, (ev) => {
    if (ev.type === "started") {
      log(`Started (${ev.tests.join(", ")})`);
    } else if (ev.type === "test_done") {
      log(`  ${ev.test_id}: ${ev.status}`);
    } else if (ev.type === "log") {
      log(`  · ${ev.msg}`);
    } else if (ev.type === "finished") {
      log("Finished — " + Object.entries(ev.summary).map(([k, v]) => `${k}: ${v}`).join("  "));
    } else if (ev.type === "result") {
      result = ev.result;
    } else if (ev.type === "error") {
      failure = ev.error || "ScanError";
    }
  });
  if (failure) throw new Error(`the scan failed with ${failure}`);
  if (!result) throw new Error("the scan ended without a result");
  return result;
}

async function readSSE(stream, onEvent) {
  const reader = stream.getReader();
  const dec = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const parts = buf.split("\n\n");
    buf = parts.pop();
    for (const p of parts) {
      const line = p.split("\n").find((l) => l.startsWith("data: "));
      if (!line) continue;
      onEvent(JSON.parse(line.slice(6)));
    }
  }
}

function logTo(el) {
  el.hidden = false;
  el.textContent = "";
  return (line) => { el.textContent += line + "\n"; el.scrollTop = el.scrollHeight; };
}

// --- results (tabs per test) -------------------------------------------------------

function renderResults(sr) {
  if (!sr.results.some((r) => r.test_id === resultsTab)) resultsTab = "";
  const tab = (id, label, status) => `<button type="button" role="tab" class="rtab"
      id="rtab-${esc(id || "all")}" data-test="${esc(id)}" aria-controls="resultsPanel">${
      status ? `<span class="sd ${esc(status)}" aria-hidden="true"></span>` : ""}${esc(label)}${
      status ? `<span class="visually-hidden"> · ${esc(status)}</span>` : ""}</button>`;
  $("results").innerHTML = `<div class="rtabs" role="tablist" aria-label="Results by test">${
    tab("", "All tests")}${sr.results.map((r) =>
      tab(r.test_id, testNames[r.test_id] || r.test_id, r.status)).join("")}</div>
    <div id="resultsPanel" role="tabpanel" tabindex="0"></div>`;
  selectResultsTab(resultsTab);
}

function selectResultsTab(testId) {
  resultsTab = testId;
  document.querySelectorAll('#results [role="tab"]').forEach((t) => {
    const on = t.dataset.test === testId;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    if (on) $("resultsPanel").setAttribute("aria-labelledby", t.id);
  });
  renderResultsPanel(lastResult, testId);
}

function setupResultsTabs() {
  const box = $("results");
  box.addEventListener("click", (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (tab) selectResultsTab(tab.dataset.test);
  });
  // Arrow keys, Home and End move between tabs (WAI-ARIA tabs pattern).
  box.addEventListener("keydown", (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (!tab) return;
    const tabs = Array.from(box.querySelectorAll('[role="tab"]'));
    const i = tabs.indexOf(tab);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const target = tabs[(next + tabs.length) % tabs.length];
    selectResultsTab(target.dataset.test);
    target.focus();
  });
}

// Counters and table of the selected tab: every test, or only the one chosen.
function renderResultsPanel(sr, testId) {
  const shown = testId ? sr.results.filter((r) => r.test_id === testId) : sr.results;
  const rows = [];
  const counts = {};
  for (const r of shown) {
    for (const f of r.findings) {
      counts[f.status] = (counts[f.status] || 0) + 1;
      const rec = f.recommendation ? ` — <span class="muted">${esc(f.recommendation)}</span>` : "";
      const lead = testId ? "" : `<td>${esc(r.category)}</td><td class="tid">${esc(r.test_id)}</td>`;
      rows.push(`<tr data-st="${esc(f.status)}" title="${esc(f.id)}">${lead}
        <td><span class="st ${esc(f.status)}">${esc(f.status)}</span></td>
        <td>${esc(f.summary)}${rec}</td></tr>`);
    }
  }
  // Counters per status; PASS, WARN and FAIL always show, the rest only when present.
  const kpis = ["PASS", "WARN", "FAIL", "ERROR", "INFO", "SKIP"]
    .filter((s) => counts[s] || ["PASS", "WARN", "FAIL"].includes(s))
    .map((s) => `<div class="kpi ${s}${counts[s] ? "" : " zero"}"><span class="n">${counts[s] || 0}</span>
      <span class="l">${s}</span></div>`).join("");
  const r = shown[0];
  const meta = testId && r ? `<p class="rmeta">${statusText(r.status)} <span class="mono">${esc(r.test_id)}</span>
    · category ${esc(r.category)} · ${esc(r.duration_ms)} ms</p>` : "";
  const head = (testId ? "" : "<th>Cat.</th><th>Test</th>") + "<th>Status</th><th>Result</th>";
  const table = rows.length
    ? `<div class="tw"><table><thead><tr>${head}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`
    : `<p class="muted">No findings.</p>`;
  $("resultsPanel").innerHTML = `<div class="kpis">${kpis}</div>${meta}${table}`;
}

function exportScan(sr, fmt) {
  if (!sr) return;
  // Exported from the server cache by scan_id (kept for the configured TTL).
  window.location = `/api/v1/scans/${sr.scan_id}/export?format=${fmt}`;
}

// --- comparison --------------------------------------------------------------------

// Colour of each change label (reuses the status classes).
const CHANGE_CLS = {
  Improved: "PASS", Regressed: "FAIL", Changed: "WARN", New: "INFO", Removed: "SKIP", Unchanged: "",
};

const FIELD_LABEL = {
  tcp_open: "TCP open", connect_ms: "TCP connect time (ms)", banner: "Banner",
  error: "Error", software: "Server version", negotiated: "Negotiated with a modern client",
  kex: "Key exchange (KEX)", server_host_key: "Host key algorithms",
  enc_s2c: "Ciphers", mac_s2c: "MACs", comp_s2c: "Compression",
  strict_kex: "Strict KEX", terrapin: "Vulnerable to Terrapin", pq_kex: "Post-quantum KEX",
  pq_kex_algs: "Post-quantum algorithms", aead: "AEAD ciphers", etm: "Encrypt-then-MAC MACs",
  fips_path: "FIPS-oriented path", auth_methods: "Authentication methods",
  auth_methods_error: "Error reading methods", host_key_fingerprints: "Host key fingerprint",
  profile: "Device profile", applicable: "Applicable",
  skip_reason: "Skip reason", runner: "Privilege path", version: "OpenSSH version",
  system: "Remote system", default: "Default sshd settings", contexts: "Match contexts",
  malformed: "Ignored sshd output",
};

// How a comparison is worded: an earlier export against the current scan, or device A
// against device B. The change values from the API stay the same; only labels differ.
const EXPORT_VIEW = {
  a: "Before", b: "Now", metaA: "Before (export)", metaB: "Now",
  noDataA: "No data in the export", noDataB: "No data in this scan",
  change: { Changed: "Different", Unchanged: "same" },
};
const DEVICE_CHANGE = {
  Improved: "Better on B", Regressed: "Worse on B", Changed: "Different",
  New: "Only on B", Removed: "Only on A", Unchanged: "same",
};
function deviceView(a, b) {
  return { a: `A · ${a}`, b: `B · ${b}`, metaA: "Device A", metaB: "Device B",
           noDataA: "No data in A", noDataB: "No data in B", change: DEVICE_CHANGE };
}

// Keys of the negotiated-algorithm maps (negotiated, fips_path).
const NEG_KEY_LABEL = { kex: "KEX", host_key: "host key", cipher: "cipher", mac: "MAC" };

function chg(c, view) {
  const label = view.change[c] || c;
  if (c === "Unchanged") return `<span class="muted">${esc(label)}</span>`;
  return `<span class="st ${CHANGE_CLS[c] || ""}">${esc(label)}</span>`;
}

function statusText(st, text) {
  if (!st) return `<span class="muted">—</span>`;
  return `<span class="st ${st}">${st}</span> ${esc(text || "")}`;
}

function fmtVal(v, cls = "") {
  if (v === null || v === undefined) return `<span class="muted">—</span>`;
  if (v === true) return "yes";
  if (v === false) return "no";
  if (typeof v === "object") return `<span class="mono ${cls}">${esc(JSON.stringify(v, null, 2))}</span>`;
  return `<span class="mono ${cls}">${esc(v)}</span>`;
}

// Lists are shown in full, one item per line, in the server's order. Given the other
// side's list, the items it lacks are highlighted.
function fmtList(list, other) {
  if (!list.length) return `<span class="muted">empty</span>`;
  const display = (x) => typeof x === "object" ? JSON.stringify(x) : String(x);
  const theirs = other ? new Set(other.map(display)) : null;
  return `<div class="mono">${list.map((x) => {
    const value = display(x);
    return theirs && !theirs.has(value) ? `<span class="only">${esc(value)}</span>` : esc(value);
  }).join("<br>")}</div>`;
}

// The Match column only says whether both sides agree; the values are in the columns
// next to it, with what differs highlighted there.
function matchCell(missing, different, view, note = "") {
  if (missing) return `<span class="muted">${esc(missing === "a" ? view.noDataA : view.noDataB)}</span>`;
  if (!different) return `<span class="muted">Same</span>`;
  return `<span class="st WARN">Different</span>` + (note ? ` <span class="muted">${esc(note)}</span>` : "");
}

function evidenceRows(fields, view) {
  const rows = [];
  const row = (label, a, b, match, highlight) =>
    `<tr class="${highlight ? "chg" : ""}"><td>${label}</td><td>${a}</td><td>${b}</td><td>${match}</td></tr>`;
  for (const f of fields) {
    const label = esc(FIELD_LABEL[f.field] || f.field);
    if (f.kind === "map") {
      const isHash = f.field === "host_key_fingerprints";
      const keyLabel = isHash ? (k) => k : (k) => NEG_KEY_LABEL[k] || k;
      // Fingerprints are long unbroken strings: let only them wrap, so they don't push
      // the other columns off screen.
      const vcls = isHash ? "hash" : "";
      for (const it of f.items) {
        const different = it.change !== "Unchanged";
        rows.push(row(`${label} · <span class="mono">${esc(keyLabel(it.key))}</span>`,
          fmtVal(it.before, vcls), fmtVal(it.after, vcls),
          matchCell(f.missing, different, view), different && !f.missing));
      }
    } else if (f.kind === "list") {
      const [a, b] = f.missing ? [null, null] : [f.after, f.before];
      rows.push(row(label, fmtList(f.before, a), fmtList(f.after, b),
        matchCell(f.missing, f.changed, view, f.reordered ? "(order)" : ""), f.changed && !f.missing));
    } else {
      rows.push(row(label, fmtVal(f.before), fmtVal(f.after),
        matchCell(f.missing, f.changed, view), f.changed && !f.missing));
    }
  }
  return rows.join("");
}

function countsText(counts, view) {
  const parts = Object.entries(counts).map(([k, v]) => `${v} ${(view.change[k] || k).toLowerCase()}`);
  return parts.length ? parts.join(" · ") : "none";
}

function renderCompare(res, target, view) {
  const a = res.meta.a, b = res.meta.b;
  const when = (iso) => new Date(iso).toLocaleString();
  const metaRows = [
    ["Device", `${a.target_host}:${a.port}`, `${b.target_host}:${b.port}`],
    ["Name", a.target_name || "—", b.target_name || "—"],
    ["Date", when(a.started_at), when(b.started_at)],
    ["Profile", a.profile, b.profile],
    ["Policy", a.policy_name, b.policy_name],
    ["Run by", a.run_by || "—", b.run_by || "—"],
    ["Tool version", a.tool_version, b.tool_version],
  ].map(([k, x, y]) => `<tr class="${x === y || k === "Date" || k === "Run by" ? "" : "chg"}">
      <td>${k}</td><td>${esc(x)}</td><td>${esc(y)}</td></tr>`).join("");

  const warn = res.warnings.length
    ? `<p class="WARN">⚠ ${res.warnings.map(esc).join("<br>⚠ ")}</p>` : "";

  let html = warn +
    `<p><strong>Tests:</strong> ${esc(countsText(res.summary.tests, view))}<br>
     <strong>Findings:</strong> ${esc(countsText(res.summary.findings, view))}<br>
     <span class="muted">In the data tables, <span class="only">highlighted</span> items exist on that side only.</span></p>
     <div class="tw"><table><thead><tr><th></th><th>${esc(view.metaA)}</th><th>${esc(view.metaB)}</th></tr></thead>
     <tbody>${metaRows}</tbody></table></div>`;

  for (const t of res.tests) {
    const name = testNames[t.test_id] || t.test_id;
    html += `<h4 class="cmph">${esc(name)} <span class="muted mono">${esc(t.test_id)}</span>
      · ${statusText(t.status_a)} → ${statusText(t.status_b)} · ${chg(t.change, view)}</h4>`;

    const frows = t.findings.map((f) => {
      const rec = f.recommendation && f.status_b !== "PASS" && f.status_b !== "INFO"
        ? `<br><span class="muted">${esc(f.recommendation)}</span>` : "";
      return `<tr class="${f.change === "Unchanged" ? "" : "chg"}" title="${esc(f.id)}">
        <td>${statusText(f.status_a, f.summary_a)}</td>
        <td>${statusText(f.status_b, f.summary_b)}${rec}</td>
        <td>${chg(f.change, view)}</td></tr>`;
    }).join("");
    if (frows) {
      html += `<div class="tw"><table>
        <thead><tr><th>${esc(view.a)}</th><th>${esc(view.b)}</th><th>Change</th></tr></thead>
        <tbody>${frows}</tbody></table></div>`;
    }

    const ev = res.evidence_diff[t.test_id];
    if (ev && ev.fields.length) {
      html += `<div class="tw"><table>
        <thead><tr><th>Data</th><th>${esc(view.a)}</th><th>${esc(view.b)}</th><th>Match</th></tr></thead>
        <tbody>${evidenceRows(ev.fields, view)}</tbody></table></div>`;
    }
  }
  target.innerHTML = html;
}
