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

/** Turn a code <input> into six boxes, one digit each. The original input stays the form's value
 *  (hidden), so the rest of the code reads it as before. Paste and phone autofill fill all boxes,
 *  Backspace goes back, and the form submits by itself when the sixth digit is typed. */
function otp(input, length = 6) {
  if (input.dataset.otp) return;
  input.dataset.otp = "1";
  input.required = false;
  input.tabIndex = -1;
  input.setAttribute("aria-hidden", "true");
  input.classList.add("otp-source");
  const label = document.querySelector(`label[for="${input.id}"]`);
  const boxes = Array.from({ length }, (_, i) => el("input", {
    class: "otp-box", inputmode: "numeric", maxlength: 1, pattern: "[0-9]", autocomplete: i ? "off" : "one-time-code",
    "aria-label": `Digit ${i + 1} of ${length}${label ? ", " + label.textContent : ""}`,
  }));
  const row = el("div", { class: "otp" }, ...boxes);
  input.after(row);

  const sync = () => {
    input.value = boxes.map((b) => b.value).join("");
    row.classList.toggle("full", input.value.length === length);
    if (input.value.length === length && input.form) input.form.requestSubmit();
  };
  const spread = (digits, from) => {
    digits = digits.replace(/\D/g, "").slice(0, length - from);
    [...digits].forEach((d, k) => { boxes[from + k].value = d; });
    boxes[Math.min(from + digits.length, length - 1)].focus();
    sync();
  };
  boxes.forEach((b, i) => {
    b.addEventListener("input", () => {
      const v = b.value.replace(/\D/g, "");
      b.value = "";
      if (v) spread(v, i); else sync();
    });
    b.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !b.value && i > 0) { boxes[i - 1].value = ""; boxes[i - 1].focus(); sync(); e.preventDefault(); }
      else if (e.key === "ArrowLeft" && i > 0) { boxes[i - 1].focus(); e.preventDefault(); }
      else if (e.key === "ArrowRight" && i < length - 1) { boxes[i + 1].focus(); e.preventDefault(); }
    });
    b.addEventListener("paste", (e) => { e.preventDefault(); spread((e.clipboardData || window.clipboardData).getData("text"), i); });
    b.addEventListener("focus", () => b.select());
  });
  input.otpReset = () => { boxes.forEach((b) => { b.value = ""; }); input.value = ""; row.classList.remove("full"); };
  input.otpFocus = () => boxes[Math.min(input.value.length, length - 1)].focus();
  input.otpShake = () => { row.classList.remove("bad"); void row.offsetWidth; row.classList.add("bad"); };
  input.focus = () => input.otpFocus();
}

// ---------------------------------------------------------------- password rules (same as backend/app/auth.py)
const PW_MIN = 12;
const PW_COMMON = new Set(["password", "passw", "qwerty", "qwertyuiop", "asdfgh", "zxcvbn", "letmein", "welcome", "admin",
  "administrator", "iloveyou", "monkey", "dragon", "football", "baseball", "sunshine", "princess", "master", "shadow",
  "superman", "batman", "trustno", "abc", "abcdef", "abcdefgh", "test", "user", "login", "secret", "changeme", "default",
  "talon", "investigator", "attack", "egypt", "cairo"]);
function passwordRules(pw, username = "", email = "") {
  const letters = pw.toLowerCase().replace(/[^a-z]/g, "");
  const personal = [username, (email || "").split("@")[0]].filter((x) => x && x.length >= 3).map((x) => x.toLowerCase());
  return [
    [`At least ${PW_MIN} characters`, pw.length >= PW_MIN],
    ["An upper-case and a lower-case letter", /[A-Z]/.test(pw) && /[a-z]/.test(pw)],
    ["A number", /[0-9]/.test(pw)],
    ["A symbol, such as ! @ # $ or a space", /[^A-Za-z0-9]/.test(pw)],
    ["Not your user name or e-mail", !personal.some((x) => pw.toLowerCase().includes(x))],
    ["Not a common password", !PW_COMMON.has(letters) && new Set(pw).size >= 5],
  ];
}
/** A compact strength bar with one line of text, for forms where the full checklist is too tall. */
const PW_SHORT = [`${PW_MIN}+ characters`, "upper and lower case", "a number", "a symbol", "not your name or e-mail", "not a common password"];
function passwordMeter(input, who = () => ["", ""]) {
  const bars = Array.from({ length: 6 }, () => el("i"));
  const text = el("span", { class: "pw-text" });
  const box = el("div", { class: "pw-meter", "aria-live": "polite" }, el("div", { class: "pw-bars" }, bars), text);
  const draw = () => {
    const pw = input.value;
    const rules = passwordRules(pw, ...who());
    const passed = rules.filter(([, ok]) => ok).length;
    const level = !pw ? "" : passed === 6 ? "ok" : passed >= 4 ? "mid" : "bad";
    box.className = "pw-meter" + (level ? " " + level : "");
    bars.forEach((b, i) => b.classList.toggle("on", !!pw && i < passed));
    const missing = rules.map(([, ok], i) => (ok ? null : PW_SHORT[i])).filter(Boolean);
    text.textContent = !pw ? `${PW_MIN}+ characters, upper and lower case, a number, a symbol.`
      : missing.length ? "Still needs: " + missing.join(", ") + "." : "Strong password.";
  };
  input.addEventListener("input", draw);
  box.redraw = draw;
  draw();
  return box;
}
