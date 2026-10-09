"use strict";

// SSH Security Auditor — the device-audit page (Steps 1–5). Shared pieces (credentials,
// scan streaming, results rendering, comparison) live in core.js, loaded first; this
// file holds the step forms, the profile/policy management, the test catalog, and the
// run/compare glue specific to this page.

const KINDS = {
  profiles: { select: "profile", meta: "profileMeta", msg: "profileMsg", noun: "profile" },
  policies: { select: "policy", meta: "policyMeta", msg: "policyMsg", noun: "policy" },
};
const items = { profiles: [], policies: [] };

const TOKENS_KEY = "sshAuditor.ownerTokens";
const ENGINEER_KEY = "sshAuditor.engineer";

function ownerToken(kind, id) { return local.get(TOKENS_KEY, {})[`${kind}/${id}`]; }
function setOwnerToken(kind, id, token) {
  const all = local.get(TOKENS_KEY, {});
  if (token) all[`${kind}/${id}`] = token; else delete all[`${kind}/${id}`];
  local.set(TOKENS_KEY, all);
}

async function init() {
  setupThemeButton($("themeBtn"));
  $("engineer").value = local.get(ENGINEER_KEY, "");
  $("engineer").addEventListener("change", () => local.set(ENGINEER_KEY, $("engineer").value.trim()));
  setupCredentials();
  setupResultsTabs();

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
  $("confirmImpact").addEventListener("change", updateRiskyTests);
  try {
    const tests = await j("/api/v1/tests");
    testNames = Object.fromEntries(tests.map((t) => [t.id, t.name]));
    renderTests(tests);
  } catch (e) { setStatus("Could not load the test catalog: " + e.message); }

  // Restore the last result of this browser tab (kept until "Clear results").
  try {
    const saved = sessionStorage.getItem("lastResult");
    if (saved) { lastResult = JSON.parse(saved); renderResults(lastResult); enableExports(true); }
  } catch (_) {}
  if (lastResult) checkRestoredResult();

  $("selall").addEventListener("change", (e) => {
    document.querySelectorAll(".tchk:not(:disabled)").forEach((c) => (c.checked = e.target.checked));
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
      text += ` · shell ${it.shell || "unknown"} · harmless command: ${it.safe_command || "none"}`;
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

// --- test catalog (Step 3) ---------------------------------------------------------

// Tests are grouped by category, A to D. Medium and high-impact tests go in a group of
// their own, locked until the engineer approves them.
const CATEGORIES = {
  A: ["Connectivity", "no login"],
  B: ["SSH negotiation", "no login"],
  C: ["Authentication", "logs in with the Step 2 credentials"],
  D: ["Effective sshd configuration", "logs in and reads sshd -T"],
  E: ["Memory (yescrypt)", "logs in and reads /proc/meminfo + sshd -T"],
  F: ["Concurrency", "bounded login load, stops automatically"],
};
const RISKY_IMPACTS = ["medium", "high"];

function categoryName(c) { return (CATEGORIES[c] || [`Category ${c}`])[0]; }

function testCard(t, risky) {
  const cat = risky ? `${categoryName(t.category)} · ` : "";
  const auth = t.requires_auth ? ` · auth ${t.credential_method || "any"}` : "";
  const privilege = t.privilege && t.privilege !== "none" ? ` · ${t.privilege}` : "";
  const actions = (t.actions || []).length ? ` — ${t.actions.join("; ")}` : "";
  return `<label${risky ? ' class="risky"' : ""}><input type="checkbox" class="tchk${risky ? " risky" : ""}"
     value="${esc(t.id)}"${risky ? "" : " checked"}>
     ${esc(t.name)} <span class="muted">${esc(cat)}impact ${esc(t.impact)}${esc(auth)}${esc(privilege)}${esc(actions)}</span></label>`;
}

function renderTests(tests) {
  const isRisky = (t) => RISKY_IMPACTS.includes(t.impact);
  const safe = tests.filter((t) => !isRisky(t));
  // Stable sort: tests keep the catalog order inside their category.
  const risky = tests.filter(isRisky).sort((a, b) => a.category.localeCompare(b.category));
  $("tests").innerHTML = [...new Set(safe.map((t) => t.category))].sort().map((c) => {
    const note = (CATEGORIES[c] || [])[1];
    return `<div class="tgroup"><h3 class="tgh"><span class="cat">${esc(c)}</span>${esc(categoryName(c))}${
      note ? ` <span class="muted">${esc(note)}</span>` : ""}</h3>
      <div class="tests">${safe.filter((t) => t.category === c).map((t) => testCard(t, false)).join("")}</div></div>`;
  }).join("");
  $("testsRisky").innerHTML = risky.map((t) => testCard(t, true)).join("");
  $("riskyGroup").hidden = !risky.length;
  updateRiskyTests();
}

// Without the approval the risky tests can't be selected; withdrawing it clears them.
function updateRiskyTests() {
  const approved = $("confirmImpact").checked;
  document.querySelectorAll(".tchk.risky").forEach((c) => {
    c.disabled = !approved;
    if (!approved) c.checked = false;
  });
  $("riskyHint").textContent = approved
    ? "Approved: choose which of these to run."
    : "Locked: tick the approval above to choose any of them.";
}

// --- scans -------------------------------------------------------------------------

function setStatus(msg) { $("status").textContent = msg; }
function enableExports(on) {
  ["exportJson", "exportHtml", "exportCsv", "clearResults"].forEach((id) => ($(id).disabled = !on));
  $("cmpBtn").disabled = !(on && $("cmpFile").files.length);
}

function clearResults() {
  lastResult = null;
  resultsTab = "";
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
  if (sameTarget) body.target_name = $("name").value.trim();
  return body;
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
    renderResults(lastResult);
    enableExports(true);
    setStatus("Finished.");
  } catch (e) {
    setStatus("Error: " + e.message);
  } finally {
    $("run").disabled = false;
  }
}

function exportAs(fmt) { exportScan(lastResult, fmt); }

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

// --- comparison with an earlier export ---------------------------------------------

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

init();
