"use strict";
// Shared helpers for the login and dashboard pages.
// Everything that comes from a log or the server is shown with textContent only (el() below),
// never as HTML, so an attack payload inside a log cannot run inside this dashboard.

/** Build an element. Children may be strings (always inserted as text) or nodes. */
function el(tag, attrs, ...children) {
  const svg = ["svg", "rect", "g", "line", "text", "path", "circle", "title"].includes(tag);
  const node = svg ? document.createElementNS("http://www.w3.org/2000/svg", tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.setAttribute("class", v);
    else if (k === "style") node.style.cssText = v;              // CSSOM, allowed by the page's CSP
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (sel, root = document) => root.querySelector(sel);

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/** fetch() for this server's API: same-origin cookie, JSON in and out, errors as ApiError. */
async function api(path, { method = "GET", json, body } = {}) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (json !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(json); }
  else if (body !== undefined) opts.body = body;
  let r;
  try { r = await fetch(path, opts); }
  catch { throw new ApiError(0, "The server is not reachable. Check that the backend is running."); }
  if (r.status === 204) return null;
  let data = null;
  try { data = await r.json(); } catch { /* not JSON */ }
  if (!r.ok) {
    const d = data && data.detail;
    const msg = typeof d === "string" ? d : Array.isArray(d) ? "Some fields are missing or too long." : r.statusText || "Request failed.";
    throw new ApiError(r.status, msg);
  }
  return data;
}

const NICE = {
  sqli: "SQL injection", xss: "XSS", traversal: "Path traversal", cmdi: "Command injection",
  bruteforce: "Brute force", enumeration: "Enumeration", enum: "Enumeration", scan: "Scan",
  data_theft: "Data theft", rate_limit: "Rate limit", other: "Other payload", recon: "Recon",
  intrusion: "Intrusion", exploitation: "Exploitation", block: "Block", allow: "Allow",
  nosql: "NoSQL injection", xxe: "XXE", ssrf: "SSRF", ssti: "Template injection", ldap: "LDAP injection",
  xpath: "XPath injection", log4j: "Log4Shell", tool_other: "Attack tool",
};
const nice = (x) => NICE[x] || String(x ?? "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const num = (x) => (x ?? 0).toLocaleString("en");
const pct = (x, d = 1) => `${(100 * (x || 0)).toFixed(d)}%`;

function fmtDate(sec) {
  if (!sec) return "–";
  return new Date(sec * 1000).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}
function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toISOString().replace("T", " ").slice(0, 19);
}
function fmtSpan(a, b) {
  if (!a) return "–";
  const s = fmtTime(a);
  if (!b || b === a) return s;
  const e = fmtTime(b);
  return s.slice(0, 10) === e.slice(0, 10) ? `${s} to ${e.slice(11)}` : `${s} to ${e}`;
}
