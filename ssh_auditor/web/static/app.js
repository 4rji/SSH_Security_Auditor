"use strict";

// SSH Security Auditor — frontend. Los resultados viven solo en el navegador
// (sessionStorage), nunca en el servidor. Fase 1: pruebas sin login.

const $ = (id) => document.getElementById(id);
let lastResult = null;
let testNames = {};

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
    testNames = Object.fromEntries(tests.map((t) => [t.id, t.name]));
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
  $("results").innerHTML = `<div class="tw"><table><thead><tr><th>Cat.</th><th>Prueba</th>
    <th>Estado</th><th>Resultado</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
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

// Color de cada etiqueta de cambio (reutiliza las clases de estado).
const CHANGE_CLS = {
  "Mejoró": "PASS", "Empeoró": "FAIL", "Cambió": "WARN",
  "Nueva": "INFO", "Nuevo": "INFO", "Desaparecida": "SKIP", "Desaparecido": "SKIP", "Igual": "",
};

const FIELD_LABEL = {
  tcp_open: "TCP abierto", connect_ms: "Latencia de conexión TCP (ms)", banner: "Banner",
  error: "Error", software: "Versión del servidor", negotiated: "Negociado con cliente moderno",
  kex: "Intercambio de claves (KEX)", server_host_key: "Algoritmos de host key",
  enc_s2c: "Cifrados", mac_s2c: "MACs", comp_s2c: "Compresión",
  strict_kex: "Strict KEX", terrapin: "Vulnerable a Terrapin", pq_kex: "KEX post-cuántico",
  pq_kex_algs: "Algoritmos post-cuánticos", aead: "Cifrados AEAD", etm: "MACs Encrypt-then-MAC",
  fips_path: "Camino FIPS", auth_methods: "Métodos de autenticación",
  auth_methods_error: "Error al leer métodos", host_key_fingerprints: "Huella de host key",
};

// Claves de los mapas de algoritmos negociados (negotiated, fips_path).
const NEG_KEY_LABEL = { kex: "KEX", host_key: "host key", cipher: "cifrado", mac: "MAC" };

function chg(c) {
  if (c === "Igual") return `<span class="muted">igual</span>`;
  return `<span class="st ${CHANGE_CLS[c] || ""}">${esc(c)}</span>`;
}

function statusText(st, text) {
  if (!st) return `<span class="muted">—</span>`;
  return `<span class="st ${st}">${st}</span> ${esc(text || "")}`;
}

function fmtVal(v) {
  if (v === null || v === undefined) return `<span class="muted">—</span>`;
  if (v === true) return "sí";
  if (v === false) return "no";
  return `<span class="mono">${esc(v)}</span>`;
}

function fmtList(list) {
  if (!list.length) return `<span class="muted">vacío</span>`;
  return `<details><summary>${list.length} ${list.length === 1 ? "elemento" : "elementos"}</summary>
    <div class="mono">${list.map(esc).join("<br>")}</div></details>`;
}

function evidenceRows(fields) {
  const rows = [];
  for (const f of fields) {
    const label = FIELD_LABEL[f.field] || f.field;
    if (f.kind === "map") {
      const keyLabel = f.field === "host_key_fingerprints" ? (k) => k : (k) => NEG_KEY_LABEL[k] || k;
      for (const it of f.items) {
        rows.push(`<tr class="${it.change === "Igual" ? "" : "chg"}">
          <td>${esc(label)} · <span class="mono">${esc(keyLabel(it.key))}</span></td>
          <td>${fmtVal(it.before)}</td><td>${fmtVal(it.after)}</td><td>${chg(it.change)}</td></tr>`);
      }
      continue;
    }
    let diff;
    if (f.kind === "list") {
      const bits = [
        ...f.added.map((x) => `<span class="add mono">+ ${esc(x)}</span>`),
        ...f.removed.map((x) => `<span class="rem mono">− ${esc(x)}</span>`),
      ];
      if (f.reordered) bits.push("Cambió el orden de preferencia");
      diff = bits.length ? bits.join("<br>") : `<span class="muted">sin cambios</span>`;
      rows.push(`<tr class="${f.changed ? "chg" : ""}"><td>${esc(label)}</td>
        <td>${fmtList(f.before)}</td><td>${fmtList(f.after)}</td><td>${diff}</td></tr>`);
      continue;
    }
    if (f.delta !== undefined) {
      const sign = f.delta > 0 ? "+" : "";
      const pct = f.before ? ` (${sign}${Math.round((f.delta / f.before) * 100)} %)` : "";
      diff = f.delta === 0 ? `<span class="muted">igual</span>` : `${sign}${f.delta}${pct}`;
    } else {
      diff = f.changed ? chg("Cambió") : `<span class="muted">igual</span>`;
    }
    rows.push(`<tr class="${f.changed ? "chg" : ""}"><td>${esc(label)}</td>
      <td>${fmtVal(f.before)}</td><td>${fmtVal(f.after)}</td><td>${diff}</td></tr>`);
  }
  return rows.join("");
}

function countsText(counts) {
  const parts = Object.entries(counts).map(([k, v]) => `${v} ${k.toLowerCase()}`);
  return parts.length ? parts.join(" · ") : "ninguno";
}

function renderCompare(res) {
  const a = res.meta.a, b = res.meta.b;
  const when = (iso) => new Date(iso).toLocaleString("es");
  const metaRows = [
    ["Equipo", `${a.target_host}:${a.port}`, `${b.target_host}:${b.port}`],
    ["Fecha", when(a.started_at), when(b.started_at)],
    ["Perfil", a.profile, b.profile],
    ["Política", a.policy_name, b.policy_name],
    ["Versión de la herramienta", a.tool_version, b.tool_version],
  ].map(([k, x, y]) => `<tr class="${x === y || k === "Fecha" ? "" : "chg"}">
      <td>${k}</td><td>${esc(x)}</td><td>${esc(y)}</td></tr>`).join("");

  const warn = res.warnings.length
    ? `<p class="WARN">⚠ ${res.warnings.map(esc).join("<br>⚠ ")}</p>` : "";

  let html = warn +
    `<p><strong>Pruebas:</strong> ${esc(countsText(res.summary.tests))}<br>
     <strong>Hallazgos:</strong> ${esc(countsText(res.summary.findings))}</p>
     <div class="tw"><table><thead><tr><th></th><th>Antes (exportación)</th><th>Ahora</th></tr></thead>
     <tbody>${metaRows}</tbody></table></div>`;

  for (const t of res.tests) {
    const name = testNames[t.test_id] || t.test_id;
    html += `<h4 class="cmph">${esc(name)} <span class="muted mono">${esc(t.test_id)}</span>
      · ${statusText(t.status_a)} → ${statusText(t.status_b)} · ${chg(t.change)}</h4>`;

    const frows = t.findings.map((f) => {
      const rec = f.recommendation && f.status_b !== "PASS" && f.status_b !== "INFO"
        ? `<br><span class="muted">${esc(f.recommendation)}</span>` : "";
      return `<tr class="${f.change === "Igual" ? "" : "chg"}" title="${esc(f.id)}">
        <td>${statusText(f.status_a, f.summary_a)}</td>
        <td>${statusText(f.status_b, f.summary_b)}${rec}</td>
        <td>${chg(f.change)}</td></tr>`;
    }).join("");
    if (frows) {
      html += `<div class="tw"><table>
        <thead><tr><th>Antes</th><th>Ahora</th><th>Cambio</th></tr></thead>
        <tbody>${frows}</tbody></table></div>`;
    }

    const ev = res.evidence_diff[t.test_id];
    if (ev && ev.fields.length) {
      html += `<div class="tw"><table>
        <thead><tr><th>Dato</th><th>Antes</th><th>Ahora</th><th>Diferencia</th></tr></thead>
        <tbody>${evidenceRows(ev.fields)}</tbody></table></div>`;
    }
  }
  $("compare").innerHTML = html;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

init();
