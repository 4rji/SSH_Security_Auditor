"use strict";

// SSH Security Auditor — frontend. Scan results live only in the browser
// (sessionStorage), never on the server. Profiles and policies are shared through the
// server; the owner token of each upload stays in the uploader's browser (localStorage).
// Credentials are only persisted after an explicit Save and are keyed by host:port.

const $ = (id) => document.getElementById(id);
let lastResult = null;
let testNames = {};

const KINDS = {
  profiles: { select: "profile", meta: "profileMeta", msg: "profileMsg", noun: "profile" },
  policies: { select: "policy", meta: "policyMeta", msg: "policyMsg", noun: "policy" },
};
const items = { profiles: [], policies: [] };

// localStorage can be missing or throw (private window, blocked site data).
const local = {
  get(key, fallback) {
    try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); }
    catch (_) { return fallback; }
  },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} },
};
const TOKENS_KEY = "sshAuditor.ownerTokens";
const ENGINEER_KEY = "sshAuditor.engineer";
const CREDENTIALS_KEY = "sshAuditor.credentials.v1";

function ownerToken(kind, id) { return local.get(TOKENS_KEY, {})[`${kind}/${id}`]; }
function setOwnerToken(kind, id, token) {
  const all = local.get(TOKENS_KEY, {});
  if (token) all[`${kind}/${id}`] = token; else delete all[`${kind}/${id}`];
  local.set(TOKENS_KEY, all);
}

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(await errorDetail(r));
  return r.json();
}

async function errorDetail(r) {
  try { return (await r.json()).detail || r.statusText; } catch (_) { return r.statusText || "HTTP " + r.status; }
}

async function init() {
  setupThemeButton($("themeBtn"));
  $("engineer").value = local.get(ENGINEER_KEY, "");
  $("engineer").addEventListener("change", () => local.set(ENGINEER_KEY, $("engineer").value.trim()));
  setupCredentials();

  // Profiles and policies
  for (const kind of Object.keys(KINDS)) {
    setupTools(kind);
    $(KINDS[kind].select).addEventListener("change", () => {
      updateItemMeta(kind);
      if (kind === "profiles") applyProfilePolicy();
    });
  }
  try {
    await Promise.all([loadItems("profiles"), loadItems("policies")]);
    applyProfilePolicy();
  } catch (e) { setStatus("Could not load profiles and policies: " + e.message); }

  // Test catalog
  try {
    const tests = await j("/api/v1/tests");
    testNames = Object.fromEntries(tests.map((t) => [t.id, t.name]));
    $("tests").innerHTML = tests.map((t) => {
      const auth = t.requires_auth ? ` · auth ${t.credential_method || "any"}` : "";
      const privilege = t.privilege && t.privilege !== "none" ? ` · ${t.privilege}` : "";
      const actions = (t.actions || []).length ? ` — ${t.actions.join("; ")}` : "";
      const checked = t.impact === "medium" || t.impact === "high" ? "" : " checked";
      return `<label><input type="checkbox" class="tchk" value="${esc(t.id)}"${checked}>
       ${esc(t.name)} <span class="muted">· ${esc(t.category)} · impact ${esc(t.impact)}${esc(auth)}${esc(privilege)}${esc(actions)}</span></label>`;
    }).join("");
  } catch (e) { setStatus("Could not load the test catalog: " + e.message); }

  // Restore the last result of this browser tab (kept until "Clear results").
  try {
    const saved = sessionStorage.getItem("lastResult");
    if (saved) { lastResult = JSON.parse(saved); renderResults(lastResult); enableExports(true); }
  } catch (_) {}
  if (lastResult) checkRestoredResult();

  $("selall").addEventListener("change", (e) => {
    document.querySelectorAll(".tchk").forEach((c) => (c.checked = e.target.checked));
  });
  $("run").addEventListener("click", runScan);
  $("exportJson").addEventListener("click", () => exportAs("json"));
  $("exportHtml").addEventListener("click", () => exportAs("html"));
  $("exportCsv").addEventListener("click", () => exportAs("csv"));
  $("clearResults").addEventListener("click", clearResults);
  $("cmpFile").addEventListener("change", () => { $("cmpBtn").disabled = !$("cmpFile").files.length; });
  $("cmpBtn").addEventListener("click", compareWithFile);
  $("liveRun").addEventListener("click", runLiveCompare);
  $("liveExportA").addEventListener("click", () => exportScan(liveScans.a, "json"));
  $("liveExportB").addEventListener("click", () => exportScan(liveScans.b, "json"));
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

// --- profiles and policies ---------------------------------------------------------

function current(kind) {
  const id = $(KINDS[kind].select).value;
  return items[kind].find((it) => it.id === id);
}

async function loadItems(kind, selectId) {
  const k = KINDS[kind];
  const sel = $(k.select);
  const keep = selectId || sel.value;
  items[kind] = await j(`/api/v1/${kind}`);
  sel.innerHTML = items[kind].map((it) =>
    `<option value="${esc(it.id)}">${esc(it.name)} (${it.builtin ? "built-in" : "custom"})</option>`
  ).join("");
  if (keep && items[kind].some((it) => it.id === keep)) sel.value = keep;
  updateItemMeta(kind);
}

function updateItemMeta(kind) {
  const k = KINDS[kind];
  const it = current(kind);
  let text = "";
  if (it) {
    text = it.builtin
      ? "Built-in"
      : `Custom · uploaded by ${it.uploaded_by || "unknown"}` +
        (it.uploaded_at ? ` on ${new Date(it.uploaded_at).toLocaleString()}` : "");
    if (it.description) text += ` — ${it.description}`;
    if (kind === "profiles") {
      const detectors = Object.entries(it.detection || {}).filter(([, command]) => command)
        .map(([field, command]) => `${field}: ${command}`);
      text += ` · shell ${it.shell || "unknown"} · harmless command: ${it.safe_command || "none"}`;
      if (detectors.length) text += ` · detection: ${detectors.join("; ")}`;
    }
  }
  $(k.meta).textContent = text;
  const del = document.querySelector(`.tools[data-kind="${kind}"] [data-act="delete"]`);
  del.hidden = !(it && !it.builtin && ownerToken(kind, it.id));
}

// Choosing a profile selects its default policy.
function applyProfilePolicy() {
  const prof = current("profiles");
  if (prof && items.policies.some((p) => p.id === prof.policy)) {
    $("policy").value = prof.policy;
    updateItemMeta("policies");
  }
}

function showMsg(kind, text, cls) {
  const el = $(KINDS[kind].msg);
  el.textContent = text;
  el.className = cls || "muted";
}

function setupTools(kind) {
  const box = document.querySelector(`.tools[data-kind="${kind}"]`);
  const file = box.querySelector('input[type="file"]');
  box.addEventListener("click", (e) => {
    const act = e.target.dataset && e.target.dataset.act;
    const it = current(kind);
    if (act === "download" && it) {
      window.location = `/api/v1/${kind}/${encodeURIComponent(it.id)}/yaml`;
    } else if (act === "example") {
      window.location = `/api/v1/${kind}/example.yaml`;
    } else if (act === "upload") {
      file.click();
    } else if (act === "delete" && it) {
      deleteItem(kind, it);
    }
  });
  file.addEventListener("change", async () => {
    if (file.files.length) await uploadItem(kind, file.files[0]);
    file.value = "";
  });
}

async function uploadItem(kind, f) {
  const by = $("engineer").value.trim();
  if (!by) {
    showMsg(kind, "Type your name at the top first, so other engineers know who uploaded it.", "err");
    $("engineer").focus();
    return;
  }
  local.set(ENGINEER_KEY, by);
  try {
    const res = await j(`/api/v1/${kind}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ yaml: await f.text(), uploaded_by: by }),
    });
    setOwnerToken(kind, res.id, res.owner_token);
    await loadItems(kind, res.id);
    if (kind === "profiles") applyProfilePolicy();
    showMsg(kind, `Uploaded "${res.id}". Every engineer can use it now.`, "ok");
  } catch (e) {
    showMsg(kind, "Upload failed: " + e.message, "err");
  }
}

async function deleteItem(kind, it) {
  const noun = KINDS[kind].noun;
  if (!confirm(`Delete ${noun} "${it.id}" for every engineer?`)) return;
  try {
    const r = await fetch(`/api/v1/${kind}/${encodeURIComponent(it.id)}`, {
      method: "DELETE", headers: { "X-Owner-Token": ownerToken(kind, it.id) || "" },
    });
    if (r.status !== 204) throw new Error(await errorDetail(r));
    setOwnerToken(kind, it.id, null);
    await loadItems(kind);
    if (kind === "profiles") applyProfilePolicy();
    showMsg(kind, `Deleted "${it.id}".`, "ok");
  } catch (e) {
    showMsg(kind, "Delete failed: " + e.message, "err");
  }
}

// --- scans -------------------------------------------------------------------------

function setStatus(msg) { $("status").textContent = msg; }
function enableExports(on) {
  ["exportJson", "exportHtml", "exportCsv", "clearResults"].forEach((id) => ($(id).disabled = !on));
  $("cmpBtn").disabled = !(on && $("cmpFile").files.length);
}

function clearResults() {
  lastResult = null;
  try { sessionStorage.removeItem("lastResult"); } catch (_) {}
  $("results").innerHTML = "";
  $("compare").innerHTML = "";
  $("log").textContent = "";
  $("log").hidden = true;
  enableExports(false);
  setStatus("");
}

// Exports are built from the server's cache. After a server restart (or once the cache
// TTL passes) a restored result is no longer there, so it can be viewed but not exported.
async function checkRestoredResult() {
  try {
    const r = await fetch(`/api/v1/scans/${encodeURIComponent(lastResult.scan_id)}`);
    if (r.status !== 404) return;
    ["exportJson", "exportHtml", "exportCsv"].forEach((id) => ($(id).disabled = true));
    setStatus("Result restored from this browser. The server no longer has it (restarted or " +
              "expired), so it can't be exported: run the scan again, or clear it.");
  } catch (_) {}
}

function selectedTests() {
  return Array.from(document.querySelectorAll(".tchk:checked")).map((c) => c.value);
}

function scanBody(host, port, useForm = false) {
  const body = {
    target_host: host, port: parseInt(port || "22", 10),
    profile: $("profile").value, policy: $("policy").value, tests: selectedTests(),
    run_by: $("engineer").value.trim(),
    confirm_impact: $("confirmImpact").checked,
  };
  const sameTarget = credentialTargetKey(host, port) === credentialTargetKey();
  const credential = useForm || sameTarget
    ? credentialFromForm() : savedCredential(host, port);
  if (credential && (credential.method !== "none" || credential.username)) {
    body.credentials = credential;
  }
  if (sameTarget) {
    body.target_name = $("name").value.trim();
    body.model = $("model").value.trim();
    body.firmware = $("firmware").value.trim();
    body.tags = $("tags").value.split(",").map((x) => x.trim()).filter(Boolean);
  }
  return body;
}

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

async function runScan() {
  const host = $("host").value.trim();
  if (!host) { setStatus("Enter an IP or FQDN."); return; }
  if (!selectedTests().length) { setStatus("Select at least one test."); return; }

  $("run").disabled = true;
  enableExports(false);
  $("results").innerHTML = "";
  $("compare").innerHTML = "";
  setStatus("Running…");
  try {
    lastResult = await streamScan(scanBody(host, $("port").value, true), logTo($("log")));
    try { sessionStorage.setItem("lastResult", JSON.stringify(lastResult)); } catch (_) {}
    if (lastResult.model) $("model").value = lastResult.model;
    if (lastResult.firmware) $("firmware").value = lastResult.firmware;
    renderResults(lastResult);
    enableExports(true);
    setStatus("Finished.");
  } catch (e) {
    setStatus("Error: " + e.message);
  } finally {
    $("run").disabled = false;
  }
}

// --- Step 5: scan two devices now and compare them -------------------------------

const liveScans = { a: null, b: null };

async function runLiveCompare() {
  const a = { host: $("hostA").value.trim() || $("host").value.trim(),
              port: $("portA").value || $("port").value };
  const b = { host: $("hostB").value.trim(), port: $("portB").value };
  const status = (msg) => { $("liveStatus").textContent = msg; };
  if (!a.host || !b.host) { status("Enter device A and device B (A defaults to the Step 1 target)."); return; }
  if (!selectedTests().length) { status("Select at least one test in Step 3."); return; }

  $("liveRun").disabled = true;
  $("liveExportA").disabled = $("liveExportB").disabled = true;
  $("liveCompare").innerHTML = "";
  liveScans.a = liveScans.b = null;
  // Progress of each scan, shown only while they run (and kept if one fails).
  $("logTitleA").textContent = `Device A · ${a.host}:${a.port || 22}`;
  $("logTitleB").textContent = `Device B · ${b.host}:${b.port || 22}`;
  $("liveLogs").hidden = false;
  status(`Scanning A (${a.host}) and B (${b.host})…`);
  try {
    const [ra, rb] = await Promise.allSettled([
      streamScan(scanBody(a.host, a.port), logTo($("logA"))),
      streamScan(scanBody(b.host, b.port), logTo($("logB"))),
    ]);
    if (ra.status === "fulfilled") { liveScans.a = ra.value; $("liveExportA").disabled = false; }
    if (rb.status === "fulfilled") { liveScans.b = rb.value; $("liveExportB").disabled = false; }
    const failed = [["A", ra], ["B", rb]].filter(([, r]) => r.status === "rejected")
      .map(([n, r]) => `device ${n}: ${r.reason.message}`);
    if (failed.length) throw new Error(failed.join("; "));

    const res = await j("/api/v1/compare", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a_id: liveScans.a.scan_id, b_id: liveScans.b.scan_id }),
    });
    renderCompare(res, $("liveCompare"), deviceView(`${a.host}:${liveScans.a.port}`,
                                                    `${b.host}:${liveScans.b.port}`));
    $("liveLogs").hidden = true;
    status("Done. B is compared against A.");
  } catch (e) {
    status("Error: " + e.message);
  } finally {
    $("liveRun").disabled = false;
  }
}

function renderResults(sr) {
  const rows = [];
  for (const r of sr.results) {
    for (const f of r.findings) {
      const rec = f.recommendation ? ` — <span class="muted">${esc(f.recommendation)}</span>` : "";
      rows.push(`<tr><td>${esc(r.category)}</td><td>${esc(r.test_id)}</td>
        <td class="st ${f.status}">${f.status}</td>
        <td>${esc(f.summary)}${rec}</td></tr>`);
    }
  }
  $("results").innerHTML = `<div class="tw"><table><thead><tr><th>Cat.</th><th>Test</th>
    <th>Status</th><th>Result</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function exportAs(fmt) { exportScan(lastResult, fmt); }

function exportScan(sr, fmt) {
  if (!sr) return;
  // Exported from the server cache by scan_id (kept for the configured TTL).
  window.location = `/api/v1/scans/${sr.scan_id}/export?format=${fmt}`;
}

// --- comparison --------------------------------------------------------------------

async function compareWithFile() {
  if (!lastResult || !$("cmpFile").files.length) return;
  const text = await $("cmpFile").files[0].text();
  let prev;
  try { prev = JSON.parse(text); } catch (_) { $("compare").innerHTML = "Invalid JSON."; return; }
  try {
    const res = await j("/api/v1/compare", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: prev, b: lastResult }),
    });
    renderCompare(res, $("compare"), EXPORT_VIEW);
  } catch (e) { $("compare").innerHTML = "Compare failed: " + esc(e.message); }
}

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
  profile: "Device profile", model: "Detected model", firmware: "Detected firmware",
  commands: "Detection commands", errors: "Detection errors", applicable: "Applicable",
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
    ["Model", a.model || "—", b.model || "—"],
    ["Firmware", a.firmware || "—", b.firmware || "—"],
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

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

init();
