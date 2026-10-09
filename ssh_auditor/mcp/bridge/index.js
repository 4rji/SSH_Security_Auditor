#!/usr/bin/env node
// Local bridge for Claude Desktop. It speaks MCP over stdio (one JSON-RPC message per
// line) and forwards each message to the SSH Security Auditor's Streamable HTTP endpoint.
// Claude's remote connectors run from Anthropic's cloud and can't reach an internal
// server; this process runs on the engineer's machine, inside the network.
// No dependencies: Node >= 18 (global fetch).
"use strict";

const readline = require("node:readline");

const SERVER = process.env.SSH_AUDITOR_URL || process.argv[2] || "";
const VERSION_KEY = "io.modelcontextprotocol/protocolVersion";
const NAME_PARAM = { "tools/call": "name", "prompts/get": "name", "resources/read": "uri" };

let sessionId = null;     // only if the server hands one out (a stateless one doesn't)
let legacyVersion = null; // version agreed in a handshake-era `initialize`

function log(text) { process.stderr.write(`[ssh-auditor bridge] ${text}\n`); }
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\n"); }

// Printable ASCII without edge spaces travels as is; anything else in MCP's base64 form.
function headerValue(v) {
  const plain = /^[\x20-\x7e]*$/.test(v) && v === v.trim() && !/^=\?base64\?.*\?=$/.test(v);
  return plain ? v : `=?base64?${Buffer.from(v, "utf8").toString("base64")}?=`;
}

function headersFor(msg) {
  const h = { "Content-Type": "application/json", "Accept": "application/json, text/event-stream" };
  if (sessionId) h["Mcp-Session-Id"] = sessionId;
  const meta = msg.params && msg.params._meta;
  const modern = meta && meta[VERSION_KEY];
  if (modern) {
    // 2026-07-28 onwards: every request repeats its version and routing in headers.
    h["MCP-Protocol-Version"] = modern;
    if (msg.method) h["Mcp-Method"] = msg.method;
    const key = NAME_PARAM[msg.method];
    if (key && typeof msg.params[key] === "string") h["Mcp-Name"] = headerValue(msg.params[key]);
  } else if (legacyVersion && msg.method !== "initialize") {
    h["MCP-Protocol-Version"] = legacyVersion;
  }
  return h;
}

function parseSSE(text) {
  const out = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data) continue;
    try { out.push(JSON.parse(data)); } catch { /* keepalive or partial event */ }
  }
  return out;
}

// Answer a request with a JSON-RPC error so the client never waits forever.
function fail(msg, text) {
  log(text);
  if (msg && msg.method && msg.id !== undefined) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: text } });
  }
}

async function forward(msg) {
  let res;
  try {
    res = await fetch(SERVER, { method: "POST", headers: headersFor(msg), body: JSON.stringify(msg) });
  } catch (e) {
    return fail(msg, `Can't reach ${SERVER}: ${(e.cause && e.cause.code) || e.message}`);
  }
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;
  if (res.status === 202 || res.status === 204) return;
  const type = res.headers.get("content-type") || "";
  const text = await res.text();
  let replies = [];
  if (type.includes("text/event-stream")) {
    replies = parseSSE(text);
  } else if (text.trim()) {
    try { const j = JSON.parse(text); replies = Array.isArray(j) ? j : [j]; } catch { /* not JSON */ }
  }
  const rpc = replies.filter((r) => r && r.jsonrpc === "2.0");
  const problem = `HTTP ${res.status} from ${SERVER}${text ? ": " + text.slice(0, 200) : ""}`;
  if (msg.method && msg.id !== undefined && !rpc.some((r) => r.id === msg.id)) {
    // Not an answer to this request (a wrong path, a proxy page, a transport error
    // with id null): report it, or the client waits until its own timeout.
    return fail(msg, problem);
  }
  if (!rpc.length && !res.ok) log(problem);
  for (const r of rpc) {
    if (msg.method === "initialize" && r.id === msg.id && r.result && r.result.protocolVersion) {
      legacyVersion = r.result.protocolVersion;
    }
    send(r);
  }
}

if (!SERVER) {
  log("Set SSH_AUDITOR_URL to the auditor's MCP endpoint, e.g. http://auditor:7284/mcp");
  process.exit(1);
}

const pending = new Set();
readline.createInterface({ input: process.stdin })
  .on("line", (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { log("ignored a line that isn't JSON"); return; }
    const p = forward(msg).catch((e) => fail(msg, String(e))).finally(() => pending.delete(p));
    pending.add(p);
  })
  .on("close", async () => {
    await Promise.allSettled([...pending]);
    process.exit(0);
  });
