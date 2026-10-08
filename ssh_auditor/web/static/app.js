"use strict";

// SSH Security Auditor — frontend. Los resultados viven solo en el navegador
// (sessionStorage), nunca en el servidor. Fase 1: pruebas sin login.

const $ = (id) => document.getElementById(id);
let lastResult = null;

async function j(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch (_) { detail = r.statusText; }
    throw new Error(detail || ("HTTP " + r.status));
  }
  return r.json();
}

async function init() {
  // Perfiles y políticas
  try {
    const p = await j("/api/v1/profiles");
    $("profile").innerHTML = p.profiles.map((x) => `<option>${x}</option>`).join("");
    $("policy").innerHTML = p.policies.map((x) => `<option>${x}</option>`).join("");
  } catch (e) { setStatus("No se pudieron cargar perfiles: " + e.message); }

  // Catálogo de pruebas
  try {
    const tests = await j("/api/v1/tests");
    $("tests").innerHTML = tests.map((t) =>
      `<label><input type="checkbox" class="tchk" value="${t.id}" checked>
       ${t.name} <span class="muted">· ${t.category} · impacto ${t.impact}</span></label>`
    ).join("");
  } catch (e) { setStatus("No se pudo cargar el catálogo: " + e.message); }

  // Restaurar último resultado de la sesión del navegador
  try {
    const saved = sessionStorage.getItem("lastResult");
    if (saved) { lastResult = JSON.parse(saved); renderResults(lastResult); enableExports(true); }
  } catch (_) {}

  $("selall").addEventListener("change", (e) => {
    document.querySelectorAll(".tchk").forEach((c) => (c.checked = e.target.checked));
  });
  $("run").addEventListener("click", runScan);
  $("exportJson").addEventListener("click", () => exportAs("json"));
  $("exportHtml").addEventListener("click", () => exportAs("html"));
  $("exportCsv").addEventListener("click", () => exportAs("csv"));
  $("cmpFile").addEventListener("change", () => { $("cmpBtn").disabled = !$("cmpFile").files.length; });
  $("cmpBtn").addEventListener("click", compareWithFile);
}

function setStatus(msg) { $("status").textContent = msg; }
function enableExports(on) {
  ["exportJson", "exportHtml", "exportCsv"].forEach((id) => ($(id).disabled = !on));
  $("cmpBtn").disabled = !(on && $("cmpFile").files.length);
}

function selectedTests() {
  return Array.from(document.querySelectorAll(".tchk:checked")).map((c) => c.value);
}

async function runScan() {
  const host = $("host").value.trim();
  if (!host) { setStatus("Indica una IP o FQDN."); return; }
  const tests = selectedTests();
  if (!tests.length) { setStatus("Selecciona al menos una prueba."); return; }

  const body = {
    target_host: host, port: parseInt($("port").value || "22", 10),
    profile: $("profile").value, policy: $("policy").value, tests,
  };
  $("run").disabled = true;
  enableExports(false);
  $("results").innerHTML = "";
  $("compare").innerHTML = "";
  $("log").hidden = false;
  $("log").textContent = "";
  setStatus("Ejecutando…");

  try {
    const r = await fetch("/api/v1/scans/stream", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    if (!r.ok) {
      let d; try { d = (await r.json()).detail; } catch (_) { d = r.statusText; }
      throw new Error(d);
    }
    await readSSE(r.body);
  } catch (e) {
    setStatus("Error: " + e.message);
  } finally {
    $("run").disabled = false;
  }
}

async function readSSE(stream) {
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
      handleEvent(JSON.parse(line.slice(6)));
    }
  }
}

function handleEvent(ev) {
  if (ev.type === "started") {
    $("log").textContent += `Iniciado (${ev.tests.join(", ")})\n`;
  } else if (ev.type === "test_done") {
    $("log").textContent += `  ${ev.test_id}: ${ev.status}\n`;
  } else if (ev.type === "log") {
    $("log").textContent += `  · ${ev.msg}\n`;
  } else if (ev.type === "finished") {
    const s = Object.entries(ev.summary).map(([k, v]) => `${k}: ${v}`).join("  ");
    setStatus("Terminado — " + s);
  } else if (ev.type === "result") {
    lastResult = ev.result;
    try { sessionStorage.setItem("lastResult", JSON.stringify(lastResult)); } catch (_) {}
    renderResults(lastResult);
    enableExports(true);
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
  $("results").innerHTML = `<table><thead><tr><th>Cat.</th><th>Prueba</th>
    <th>Estado</th><th>Resultado</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

async function exportAs(fmt) {
  if (!lastResult) return;
  // Exportación desde la caché del servidor por scan_id (sobrevive al TTL configurado).
  window.location = `/api/v1/scans/${lastResult.scan_id}/export?format=${fmt}`;
}

async function compareWithFile() {
  if (!lastResult || !$("cmpFile").files.length) return;
  const text = await $("cmpFile").files[0].text();
  let prev;
  try { prev = JSON.parse(text); } catch (_) { $("compare").innerHTML = "JSON inválido."; return; }
  try {
    const res = await j("/api/v1/compare", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: prev, b: lastResult }),
    });
    renderCompare(res);
  } catch (e) { $("compare").innerHTML = "Error al comparar: " + esc(e.message); }
}

function renderCompare(res) {
  const rows = res.tests.map((t) =>
    `<tr><td>${esc(t.test_id)}</td><td>${esc(t.change)}</td>
     <td>${t.status_a || "—"}</td><td>${t.status_b || "—"}</td></tr>`).join("");
  let warn = res.warnings.length
    ? `<p class="muted">⚠ ${res.warnings.map(esc).join("<br>⚠ ")}</p>` : "";
  let diffs = "";
  for (const [tid, d] of Object.entries(res.evidence_diff)) {
    const bits = [];
    if (d.host_key_changed) bits.push("<strong>host key cambió</strong>");
    for (const f of ["kex", "server_host_key", "enc_s2c", "mac_s2c"]) {
      if (d[f] && (d[f].added.length || d[f].removed.length)) {
        bits.push(`${f}: +[${d[f].added.map(esc).join(", ")}] −[${d[f].removed.map(esc).join(", ")}]`);
      }
    }
    if (bits.length) diffs += `<li><strong>${esc(tid)}</strong>: ${bits.join("; ")}</li>`;
  }
  $("compare").innerHTML = warn +
    `<table><thead><tr><th>Prueba</th><th>Cambio</th><th>Antes</th><th>Ahora</th></tr></thead>
     <tbody>${rows}</tbody></table>` +
    (diffs ? `<ul class="muted">${diffs}</ul>` : "");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

init();
