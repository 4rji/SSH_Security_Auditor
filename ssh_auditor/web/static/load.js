"use strict";

// Load testing page: drives the memory (E) and concurrency (F) tests through the same
// scan endpoint as the auditor, reusing core.js for credentials, streaming, results and
// comparison. This page is dedicated to these tests, so it approves their impact itself.

const ENGINEER_KEY = "sshAuditor.engineer";

function setStatus(msg) { $("status").textContent = msg; }

function enableExports(on) {
  ["exportJson", "exportHtml", "exportCsv", "clearResults"].forEach((id) => ($(id).disabled = !on));
  $("cmpBtn").disabled = !(on && $("cmpFile").files.length);
}

async function loadProfiles() {
  const profiles = await j("/api/v1/profiles");
  $("profile").innerHTML = profiles.map((p) =>
    `<option value="${esc(p.id)}">${esc(p.name)} (${p.builtin ? "built-in" : "custom"})</option>`
  ).join("");
  if (profiles.some((p) => p.id === "generic")) $("profile").value = "generic";
}

function renderLoadTests(tests) {
  // Only the Phase 4 tests belong on this page.
  const here = tests.filter((t) => t.category === "E" || t.category === "F");
  $("loadTests").innerHTML = here.map((t) => {
    const privilege = t.privilege && t.privilege !== "none" ? ` · ${t.privilege}` : "";
    const checked = t.impact === "medium" || t.impact === "high" ? "" : " checked";
    return `<label><input type="checkbox" class="ltchk" value="${esc(t.id)}"${checked}>
      ${esc(t.name)} <span class="muted">· category ${esc(t.category)} · impact ${esc(t.impact)}${esc(privilege)}</span></label>`;
  }).join("");
  // Concurrency parameters only matter when a concurrency test exists.
  $("loadParams").hidden = !here.some((t) => t.category === "F");
}

function selectedLoadTests() {
  return Array.from(document.querySelectorAll(".ltchk:checked")).map((c) => c.value);
}

function loadScanBody() {
  const load = {};
  const it = parseInt($("iterations").value, 10);
  if (!Number.isNaN(it)) load.iterations = it;
  const er = parseInt($("errorRatePct").value, 10);
  if (!Number.isNaN(er)) load.error_rate_pct = er;
  const pf = parseFloat($("p95Factor").value);
  if (!Number.isNaN(pf)) load.p95_factor = pf;

  const body = {
    target_host: $("host").value.trim(), port: parseInt($("port").value || "22", 10),
    profile: $("profile").value, tests: selectedLoadTests(),
    run_by: $("engineer").value.trim(), target_name: $("name").value.trim(),
    // This page is dedicated to the memory and concurrency tests, so it approves their
    // medium/high impact itself.
    confirm_impact: true, params: { load },
  };
  const cc = parseInt($("concurrency").value, 10);
  if (!Number.isNaN(cc)) body.concurrency = cc;
  const credential = credentialFromForm();
  if (credential && (credential.method !== "none" || credential.username)) {
    body.credentials = credential;
  }
  return body;
}

async function runLoad() {
  const host = $("host").value.trim();
  if (!host) { setStatus("Enter an IP or FQDN."); return; }
  if (!selectedLoadTests().length) { setStatus("Select at least one test."); return; }

  $("runLoad").disabled = true;
  enableExports(false);
  $("results").innerHTML = "";
  $("compare").innerHTML = "";
  setStatus("Running…");
  try {
    lastResult = await streamScan(loadScanBody(), logTo($("log")));
    try { sessionStorage.setItem("loadLastResult", JSON.stringify(lastResult)); } catch (_) {}
    renderResults(lastResult);
    enableExports(true);
    setStatus("Finished.");
  } catch (e) {
    setStatus("Error: " + e.message);
  } finally {
    $("runLoad").disabled = false;
  }
}

function clearResults() {
  lastResult = null;
  resultsTab = "";
  try { sessionStorage.removeItem("loadLastResult"); } catch (_) {}
  $("results").innerHTML = "";
  $("compare").innerHTML = "";
  $("log").textContent = "";
  $("log").hidden = true;
  enableExports(false);
  setStatus("");
}

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

async function init() {
  setupThemeButton($("themeBtn"));
  $("engineer").value = local.get(ENGINEER_KEY, "");
  $("engineer").addEventListener("change", () => local.set(ENGINEER_KEY, $("engineer").value.trim()));
  setupCredentials();
  setupResultsTabs();

  try {
    await loadProfiles();
  } catch (e) { setStatus("Could not load profiles: " + e.message); }
  try {
    const tests = await j("/api/v1/tests");
    testNames = Object.fromEntries(tests.map((t) => [t.id, t.name]));
    renderLoadTests(tests);
  } catch (e) { setStatus("Could not load the test catalog: " + e.message); }

  try {
    const saved = sessionStorage.getItem("loadLastResult");
    if (saved) { lastResult = JSON.parse(saved); renderResults(lastResult); enableExports(true); }
  } catch (_) {}

  $("runLoad").addEventListener("click", runLoad);
  $("exportJson").addEventListener("click", () => exportScan(lastResult, "json"));
  $("exportHtml").addEventListener("click", () => exportScan(lastResult, "html"));
  $("exportCsv").addEventListener("click", () => exportScan(lastResult, "csv"));
  $("clearResults").addEventListener("click", clearResults);
  $("cmpFile").addEventListener("change", () => { $("cmpBtn").disabled = !$("cmpFile").files.length; });
  $("cmpBtn").addEventListener("click", compareWithFile);
}

init();
