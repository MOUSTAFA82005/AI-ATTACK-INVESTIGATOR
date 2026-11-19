"use strict";
// The hero tape: an example log (documentation IP ranges, made-up requests) read line by line.
// Attack lines get their type and score; the attacker's case fills in and ends in a block.
// With reduced motion the finished state is shown at once.
(function () {
  const ATTACKER = "203.0.113.66";
  // [ip, request, kind, tag, stage]  kind: ok | hit | behaviour
  const LINES = [
    ["198.51.100.23", "GET /products?page=2", "ok", "normal"],
    ["198.51.100.40", "GET /cart", "ok", "normal"],
    [ATTACKER, "GET /.git/config", "behaviour", "Scan", "recon"],
    ["198.51.100.23", "GET /products/14", "ok", "normal"],
    [ATTACKER, "GET /backup.zip", "behaviour", "Scan", "recon"],
    ["192.0.2.18", "POST /login", "ok", "normal"],
    [ATTACKER, "GET /products?id=14'", "hit", "SQL injection 0.91", "intrusion"],
    ["198.51.100.40", "GET /checkout", "ok", "normal"],
    [ATTACKER, "GET /products?id=14 UNION SELECT email,password FROM users--", "hit", "SQL injection 0.99", "exploitation"],
    ["198.51.100.23", "GET /search?q=running+shoes", "ok", "normal"],
    [ATTACKER, "GET /download?file=../../../etc/passwd", "hit", "Path traversal 0.98", "exploitation"],
    ["192.0.2.18", "GET /account", "ok", "normal"],
    [ATTACKER, "GET /api/users/1 .. /api/users/40", "behaviour", "Enumeration", "data_theft"],
  ];

  const list = document.getElementById("tape-lines");
  const count = document.getElementById("tape-n");
  const verdict = document.getElementById("case-verdict");
  const stages = [...document.querySelectorAll(".case-stages li")];
  if (!list) return;

  let n = 0;
  function show(line) {
    const [ip, req, kind, tag, stage] = line;
    const li = document.createElement("li");
    const a = document.createElement("span"); a.className = "ip"; a.textContent = ip;
    const b = document.createElement("span"); b.className = "req"; b.textContent = req;
    const c = document.createElement("span"); c.className = "tag"; c.textContent = tag;
    li.append(a, b, c);
    list.append(li);
    while (list.children.length > 11) list.firstElementChild.remove();
    n += kind === "behaviour" && req.includes("..") ? 40 : 1;
    count.textContent = n.toLocaleString("en");
    if (kind !== "ok") li.classList.add(kind);
    else li.classList.add("ok");
    if (stage) stages.find((s) => s.dataset.stage === stage)?.classList.add("on");
  }
  function reset() {
    list.replaceChildren();
    n = 0;
    stages.forEach((s) => s.classList.remove("on"));
    verdict.textContent = "Watching";
    verdict.classList.remove("block");
  }
  function finish() {
    verdict.textContent = "Block";
    verdict.classList.add("block");
  }

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    LINES.forEach(show);
    finish();
    return;
  }

  let i = 0;
  function tick() {
    if (i < LINES.length) {
      show(LINES[i++]);
      setTimeout(tick, LINES[i - 1][2] === "ok" ? 650 : 1100);
    } else {
      finish();
      setTimeout(() => { reset(); i = 0; tick(); }, 4200);
    }
  }
  setTimeout(tick, 400);
})();

// ------------------------------------------------------------------ page motion
(function () {
  const still = window.FX ? window.FX.still : true;

  // Floating nav gets a stronger shadow once the page scrolls; the top bar shows reading progress.
  const nav = document.getElementById("nav");
  const bar = document.getElementById("progress");
  let ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const max = document.documentElement.scrollHeight - innerHeight;
      bar?.style.setProperty("--p", max > 0 ? (scrollY / max).toFixed(4) : "0");
      nav?.classList.toggle("scrolled", scrollY > 24);
      ticking = false;
    });
  }
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // Numbers count up once they are on screen.
  document.querySelectorAll(".stat").forEach((s) => {
    const go = () => s.querySelectorAll("[data-count]").forEach((n) => window.FX.countUp(n));
    if (s.classList.contains("in")) go(); else s.addEventListener("reveal", go, { once: true });
  });

  // Result bars grow from zero.
  const card = document.querySelector(".results-card");
  if (card) {
    const grow = () => card.querySelectorAll(".bar-cell").forEach((b) => b.style.setProperty("--w", `${b.dataset.w}%`));
    if (card.classList.contains("in")) grow(); else card.addEventListener("reveal", grow, { once: true });
  }

  // A firewall rule typed out in the bento card, then repeated.
  const code = document.getElementById("type-code");
  const RULE = [
    ["k", "SecRule "], ["", "REQUEST_URI "], ["s", "\"@beginsWith /products\" "], ["", "\\\n  "],
    ["", "\"id:100014,phase:2,"], ["k", "deny"], ["", ",status:403,\\\n  "],
    ["", "chain\"\n"], ["k", "  SecRule "], ["", "ARGS:id "], ["s", "\"@detectSQLi\""],
  ];
  function paint(n) {
    const frag = document.createDocumentFragment();
    let left = n;
    for (const [cls, text] of RULE) {
      if (left <= 0) break;
      const s = document.createElement("span");
      if (cls) s.className = cls;
      s.textContent = text.slice(0, left);
      left -= text.length;
      frag.append(s);
    }
    code.replaceChildren(frag);
  }
  if (code) {
    const total = RULE.reduce((a, [, t]) => a + t.length, 0);
    if (still) paint(total);
    else {
      let n = 0;
      const type = () => {
        n += 2; paint(n);
        setTimeout(type, n >= total ? (n = -60, 2600) : 28);
      };
      const host = code.closest(".card");
      host.addEventListener("reveal", type, { once: true });
      if (host.classList.contains("in")) type();
    }
  }

  // Sensitive / quiet switch flips by itself.
  const toggle = document.querySelector(".toggle-demo");
  if (toggle && !still) {
    const opts = toggle.querySelectorAll(".td-opt");
    setInterval(() => {
      const quiet = toggle.classList.toggle("quiet");
      opts[0].classList.toggle("on", !quiet);
      opts[1].classList.toggle("on", quiet);
    }, 2600);
  }

  // Pipeline: a pulse walks from model to model.
  const nodes = [...document.querySelectorAll(".pipe-nodes li")];
  if (nodes.length && !still) {
    let i = 0;
    setInterval(() => {
      nodes.forEach((n, j) => n.classList.toggle("active", j === i));
      i = (i + 1) % nodes.length;
    }, 900);
  }

  // Footer status: the open /health endpoint says whether the models are loaded.
  const status = document.getElementById("status");
  const text = document.getElementById("status-text");
  if (status && text) {
    fetch("/health", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((h) => {
        status.classList.add(h.model_loaded ? "ok" : "warn");
        text.textContent = h.model_loaded ? "All systems running · models loaded" : "Server up · models not loaded";
      })
      .catch(() => { status.classList.add("bad"); text.textContent = "Server not reachable"; });
  }
})();
