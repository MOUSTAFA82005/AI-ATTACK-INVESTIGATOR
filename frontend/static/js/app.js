"use strict";
// The dashboard: a small hash router over Overview, New investigation, Investigations,
// one investigation, and Account. All data comes from the API, which checks the login
// on every call; a 401 sends the browser back to the login page.
(function () {
  const view = $("#view");
  const LEVELS = ["critical", "high", "medium", "low", "none"];
  const STAGES = ["recon", "intrusion", "exploitation", "data_theft"];
  const MODES = {
    sensitive: ["Sensitive", "Threshold 0.7, the preregistered default. Catches more."],
    quiet: ["Quiet", "Threshold 0.8. Fewer false alarms, misses more attacks."],
  };
  let me = null;
  const put = (...nodes) => view.replaceChildren(...nodes.filter(Boolean));
  let mode = "sensitive";
  try { if (localStorage.getItem("aai-mode") === "quiet") mode = "quiet"; } catch { /* private mode */ }
  /** The detection mode, remembered in this browser for the New investigation page. */
  function setMode(k) {
    mode = k;
    try { localStorage.setItem("aai-mode", k); } catch { /* private mode */ }
    for (const r of document.querySelectorAll('input[name="mode"]')) r.checked = r.value === k;
  }

  async function call(path, opts) {
    try { return await api(path, opts); }
    catch (e) {
      if (e.status === 401 || e.status === 503) location.replace("/login");
      throw e;
    }
  }

  // ---------------------------------------------------------------- shell
  function setPage(title, actions = []) {
    $("#page-title").textContent = title;
    $("#page-actions").replaceChildren(...actions);
    document.title = `${title} · TALON INVESTIGATOR`;
  }
  function setNav(route) {
    for (const a of document.querySelectorAll(".side-nav a")) {
      if (a.dataset.route === route) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }
  function closeMenu() {
    $("#side").classList.remove("open");
    $("#scrim").hidden = true;
    $("#menu").setAttribute("aria-expanded", "false");
  }
  function failed(err) {
    put(el("div", { class: "notice error", role: "alert" }, err.message || String(err)));
  }
  function loading() {
    put(el("p", { class: "muted" }, el("span", { class: "spinner" }), "  Loading…"));
  }

  async function route() {
    closeMenu();
    Falcon.favicon("watch");
    const [, name, arg, section] = (location.hash || "#/home").split("/");
    refreshSide();
    if (name !== "search" && document.activeElement !== $("#side-q")) $("#side-q").value = "";
    try {
      if (name === "new") { setNav("new"); return renderNew(); }
      if (name === "history") { setNav("history"); return await renderHistory(); }
      if (name === "attackers") { setNav("attackers"); return await renderAttackers(); }
      if (name === "recent") { setNav("recent"); return await renderRecent(); }
      if (name === "notifications") { setNav("notifications"); return await renderNotifications(arg || "all"); }
      if (name === "search") { setNav("search"); return await renderSearch(); }
      if (name === "inv" && arg) { setNav("history"); return await renderInvestigation(arg, section || "summary"); }
      if (name === "account") { setNav("account"); return await renderAccount(); }
      setNav("home");
      return await renderHome();
    } catch (e) { failed(e); }
    finally { view.focus({ preventScroll: true }); }
  }

  // ---------------------------------------------------------------- tooltip (charts)
  const tip = el("div", { class: "tip", role: "status", hidden: true });
  document.body.append(tip);
  function hoverTip(node, text) {
    const showAt = (x, y) => { tip.textContent = text; tip.hidden = false; tip.style.left = `${Math.min(x + 14, innerWidth - 270)}px`; tip.style.top = `${y + 14}px`; };
    node.addEventListener("mousemove", (e) => showAt(e.clientX, e.clientY));
    node.addEventListener("mouseleave", () => { tip.hidden = true; });
    node.addEventListener("focus", () => { const r = node.getBoundingClientRect(); showAt(r.left, r.top); });
    node.addEventListener("blur", () => { tip.hidden = true; });
  }

  // ---------------------------------------------------------------- overview
  async function renderHome() {
    setPage("Overview", [el("a", { class: "btn btn-primary btn-small", href: "#/new" }, "New investigation")]);
    loading();
    const s = await call("/api/stats");
    if (!s.investigations) {
      put(emptyState("No investigations yet", "The falcon is waiting. Upload an access log to see who attacked the site, how far they got and what to block."));
      return;
    }
    const t = s.totals;
    const blocked = s.actions.block || 0;
    const last = s.recent[0] || {};
    put(
      el("a", { class: "verdict-link", href: `#/inv/${last.id}` }, verdict(last.attack_requests || 0, last.sessions_flagged || 0, last.filename)),
      el("section", { class: "kpis", "aria-label": "Totals over all your investigations" },
        kpi("Logs investigated", num(s.investigations), `latest ${fmtDate(s.recent[0]?.created_at)}`),
        kpi("Requests read", num(t.parsed), "across all logs"),
        kpi("Attack requests", num(t.attack_requests), `${pct(t.attack_requests / Math.max(1, t.parsed))} of requests`, "threat"),
        kpi("Visitors flagged", num(t.sessions_flagged), `of ${num(t.sessions_total)} visitors`),
        kpi("Suggested blocks", num(blocked), `${num(s.actions.rate_limit || 0)} rate limits`)),
      el("div", { class: "grid grid-2" },
        panel("Attack requests per log", `last ${s.trend.length} investigations`, trendChart(s.trend)),
        panel("Attack types", "requests, all logs", typeBars(s.types))),
      el("div", { class: "grid grid-2e" },
        panel("Visitors by risk", "all visitors, all logs", levelStack(s.levels)),
        panel("How far attackers got", "visitors that reached each stage", stageBars(s.stages))),
      el("div", { class: "grid grid-2" },
        panel("Most dangerous visitors", "highest risk seen", attackersTable(s.top_attackers)),
        panel("Recent investigations", null, recentList(s.recent))),
    );
  }
  /** The falcon's verdict on one log: red eye when attacks were found, green when it looks clean. */
  function verdict(attacks, flagged, filename, size = 64) {
    const bad = attacks > 0 || flagged > 0;
    const f = Falcon.make({ size, state: bad ? "threat" : "safe", label: bad ? "Attacks found" : "No attacks found" });
    return el("section", { class: `verdict ${bad ? "bad" : "good"}` }, f,
      el("div", {},
        el("div", { class: "verdict-k" }, filename ? `Latest log · ${filename}` : "This log"),
        el("div", { class: "verdict-v" }, bad ? `${num(attacks)} attack requests · ${num(flagged)} suspicious visitors` : "No attacks found"),
        el("div", { class: "verdict-s" }, bad ? "The falcon's eye is red: open the visitors to see who did what and what to block." : "The falcon's eye is green: nothing in this log looks like an attack.")));
  }
  function emptyState(title, text) {
    return el("div", { class: "panel empty" }, Falcon.make({ size: 96, state: "sleep" }),
      el("h2", {}, title), el("p", {}, text), el("a", { class: "btn btn-primary", href: "#/new" }, "Investigate a log"));
  }
  function kpi(k, v, sub, cls) {
    return el("div", { class: `kpi ${cls || ""}` }, el("div", { class: "kpi-k" }, k), el("div", { class: "kpi-v" }, v), el("div", { class: "kpi-s" }, sub));
  }
  function panel(title, sub, body) {
    return el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, title), sub ? el("span", { class: "panel-sub" }, sub) : null), body);
  }

  function trendChart(trend) {
    const W = 640, H = 220, L = 44, B = 28, T = 10;
    const max = Math.max(1, ...trend.map((d) => d.attack_requests));
    const step = niceStep(max);
    const top = Math.ceil(max / step) * step;
    const y = (v) => T + (H - T - B) * (1 - v / top);
    const slot = (W - L) / Math.max(trend.length, 1);
    const bw = Math.min(42, slot * 0.6);
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Attack requests in the last ${trend.length} logs` });
    for (let v = 0; v <= top; v += step) {
      svg.append(el("line", { class: v ? "grid-line" : "axis", x1: L, x2: W, y1: y(v), y2: y(v) }),
        el("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, num(v)));
    }
    trend.forEach((d, i) => {
      const x = L + slot * i + (slot - bw) / 2;
      const h = Math.max(d.attack_requests ? 2 : 0, y(0) - y(d.attack_requests));
      const r = Math.min(4, bw / 2, h);
      // Rounded top, square base: a path keeps the bar anchored to the axis.
      const p = `M${x},${y(0)} V${y(0) - h + r} Q${x},${y(0) - h} ${x + r},${y(0) - h} H${x + bw - r} Q${x + bw},${y(0) - h} ${x + bw},${y(0) - h + r} V${y(0)} Z`;
      const bar = el("path", { class: "bar", d: p, tabindex: 0, role: "link", "aria-label": `${d.filename}: ${d.attack_requests} attack requests` });
      bar.addEventListener("click", () => { location.hash = `#/inv/${d.id}`; });
      bar.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = `#/inv/${d.id}`; });
      hoverTip(bar, `${d.filename}\n${num(d.attack_requests)} attack requests of ${num(d.parsed)}\n${fmtDate(d.created_at)}`);
      svg.append(bar);
      svg.append(el("text", { x: x + bw / 2, y: H - 8, "text-anchor": "middle" }, new Date(d.created_at * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short" })));
    });
    return el("div", { class: "trend" }, svg, el("p", { class: "note" }, "Click a bar to open that investigation."));
  }
  function niceStep(max) {
    const raw = max / 4, mag = 10 ** Math.floor(Math.log10(raw));
    return [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) || mag * 10;
  }
  function hbars(items, cls) {
    const max = Math.max(1, ...items.map(([, v]) => v));
    return el("div", { class: "hbars" }, items.map(([label, v]) =>
      el("div", { class: "hbar" }, el("span", {}, label),
        el("div", { class: "hbar-track" }, el("div", { class: `hbar-fill ${cls || ""}`, style: `width:${(100 * v) / max}%` })),
        el("span", { class: "hbar-v" }, num(v)))));
  }
  function typeBars(types) {
    const items = Object.entries(types);
    if (!items.length) return el("p", { class: "muted" }, "No attacks found yet.");
    const top = items.slice(0, 7);
    const rest = items.slice(7).reduce((a, [, v]) => a + v, 0);
    if (rest) top.push(["other", rest]);
    return hbars(top.map(([k, v]) => [nice(k), v]));
  }
  function stageBars(stages) {
    return hbars(STAGES.map((s) => [nice(s), stages[s] || 0]), "stage");
  }
  function levelStack(levels) {
    const total = LEVELS.reduce((a, l) => a + (levels[l] || 0), 0) || 1;
    return el("div", {},
      el("div", { class: "stack", role: "img", "aria-label": LEVELS.map((l) => `${levels[l] || 0} ${l}`).join(", ") },
        LEVELS.filter((l) => levels[l]).map((l) => {
          const s = el("span", { class: `lv-${l}-bg`, style: `width:${(100 * levels[l]) / total}%` });
          hoverTip(s, `${nice(l)}: ${num(levels[l])} visitors`);
          return s;
        })),
      el("div", { class: "legend" }, LEVELS.map((l) => el("span", {}, el("i", { class: `lv-${l}-bg` }), `${nice(l)} ${num(levels[l] || 0)}`))));
  }
  function attackersTable(list) {
    if (!list.length) return el("p", { class: "muted" }, "No flagged visitors yet.");
    return el("div", { class: "table-wrap" }, el("table", { class: "t" },
      el("thead", {}, el("tr", {}, el("th", {}, "Visitor"), el("th", {}, "Risk"), el("th", {}, "Action"), el("th", { class: "num" }, "Logs"))),
      el("tbody", {}, list.map((a) => el("tr", {},
        el("td", { class: "ipcell" }, a.ip),
        el("td", {}, el("span", { class: `badge lv-${a.risk_level}` }, `${nice(a.risk_level)} ${a.risk_score}`)),
        el("td", {}, Object.keys(a.actions).filter(Boolean).map((x) => el("span", { class: `badge act-${x}`, style: "margin-right:4px" }, nice(x)))),
        el("td", { class: "num" }, a.seen_in))))));
  }
  function recentList(items) {
    return el("div", { class: "table-wrap" }, el("table", { class: "t" },
      el("tbody", {}, items.map((it) => linkRow(`#/inv/${it.id}`,
        el("td", {}, el("div", {}, it.filename || "log"), el("div", { class: "small muted" }, fmtDate(it.created_at))),
        el("td", { class: "num" }, el("div", {}, `${num(it.attack_requests)} attacks`), el("div", { class: "small muted" }, `${num(it.parsed)} requests`)))))));
  }
  function linkRow(href, ...cells) {
    const tr = el("tr", { class: "link", tabindex: 0 }, ...cells);
    tr.addEventListener("click", () => { location.hash = href; });
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = href; });
    return tr;
  }

  // ---------------------------------------------------------------- new investigation
  function renderNew() {
    setPage("New investigation");
    let file = null;
    const input = el("input", { type: "file", accept: ".log,.txt,.json,text/plain,application/json", hidden: true });
    const fileLine = el("div", { class: "file" });
    const drop = el("div", { class: "drop", tabindex: 0, role: "button", "aria-label": "Choose a log file" },
      el("svg", { width: 44, height: 44, viewBox: "0 0 44 44", "aria-hidden": "true" },
        el("rect", { x: 9, y: 6, width: 26, height: 32, rx: 4, fill: "none", stroke: "currentColor", "stroke-width": 2, opacity: ".5" }),
        el("path", { d: "M22 28V16m-5 5 5-5 5 5", fill: "none", stroke: "currentColor", "stroke-width": 2.2, "stroke-linecap": "round", "stroke-linejoin": "round" })),
      el("h2", {}, "Drop an access log here"),
      el("p", {}, "or click to choose one. Nginx or Apache combined, JSON lines, IIS or W3C, up to 50 MB."),
      el("p", {}, "A saved result (.json) opens without running the models again."),
      fileLine, input);
    const go = el("button", { class: "btn btn-primary btn-wide", type: "button", disabled: true }, "Investigate");
    const msg = el("div", { class: "notice", role: "alert", hidden: true });
    const hawk = Falcon.make({ size: 120, state: "scan", label: "Investigating" });
    const scanBox = el("div", { class: "scanbox", hidden: true }, hawk, el("div", { class: "scan-text" }, "The falcon is reading every request…"));
    const steps = el("ol", { class: "progress", hidden: true },
      ["Uploading the log", "Scoring every request", "Following each visitor", "Naming attacks, stages and fixes"].map((s) => el("li", {}, s)));
    const modes = el("fieldset", { class: "mode", style: "border:0;padding:0;margin:0" }, el("legend", { class: "sr-only" }, "Detection mode"),
      Object.entries(MODES).map(([k, [name, text]]) => {
        const r = el("input", { type: "radio", name: "mode", value: k });
        r.checked = k === mode;
        r.addEventListener("change", () => setMode(k));
        return el("label", {}, r, el("strong", {}, name), el("span", {}, text));
      }));

    const pick = (f) => {
      file = f || null;
      fileLine.textContent = file ? `${file.name}  (${(file.size / 1048576).toFixed(1)} MB)` : "";
      go.disabled = !file;
      go.textContent = file && /\.json$/i.test(file.name) ? "Open saved result" : "Investigate";
      msg.hidden = true;
    };
    drop.addEventListener("click", () => input.click());
    drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); pick(e.dataTransfer.files[0]); });
    input.addEventListener("change", () => pick(input.files[0]));

    go.addEventListener("click", async () => {
      if (!file) return;
      msg.hidden = true;
      if (/\.json$/i.test(file.name)) {
        try {
          const data = JSON.parse(await file.text());
          if (!data || !Array.isArray(data.sessions)) throw new Error("This file is not a saved investigation.");
          current = { key: "file", data, saved: false };
          location.hash = "#/inv/file/summary";
          return;
        } catch (e) { msg.className = "notice error"; msg.textContent = `Could not open the file: ${e.message}`; msg.hidden = false; return; }
      }
      try { if ("Notification" in window && Notification.permission === "default") Notification.requestPermission(); } catch { /* not supported */ }
      go.disabled = true;
      go.replaceChildren(el("span", { class: "spinner" }), "Investigating…");
      steps.hidden = false;
      scanBox.hidden = false;
      Falcon.setState(hawk, "scan");
      const items = [...steps.children];
      let i = 0;
      const mark = () => items.forEach((li, k) => { li.className = k < i ? "done" : k === i ? "now" : ""; });
      mark();
      const timer = setInterval(() => { if (i < items.length - 1) { i++; mark(); } }, 1600);
      try {
        const fd = new FormData();
        fd.append("file", file);
        const r = await call(`/investigate?mode=${encodeURIComponent(mode)}`, { method: "POST", body: fd });
        const bad = (r.sessions_flagged || 0) > 0 || (r.sessions || []).some((x) => (x.timeline || []).some((t) => t.is_attack));
        Falcon.setState(hawk, bad ? "threat" : "safe");
        desktopAlert(bad ? "Attacks found" : "Log looks clean", `${file.name}: ${num(r.sessions_flagged || 0)} suspicious visitors.`);
        scanBox.lastChild.textContent = bad ? "Attacks found. Opening the case file…" : "Nothing found. Opening the result…";
        items.forEach((li) => { li.className = "done"; });
        await new Promise((ok) => setTimeout(ok, 1100));
        location.hash = `#/inv/${r.id}`;
      } catch (e) {
        msg.className = "notice error"; msg.textContent = e.message; msg.hidden = false;
        steps.hidden = true;
        scanBox.hidden = true;
        go.disabled = false; go.textContent = "Investigate";
      } finally { clearInterval(timer); }
    });

    put(el("div", { class: "upload" }, drop,
      el("section", { class: "panel run" }, el("h2", {}, "Detection mode"), modes, go, scanBox, steps, msg,
        el("p", { class: "note" }, "Paths, passwords, tokens and e-mails are masked before results are saved. Results are visible to your account only."))));
  }

  // ---------------------------------------------------------------- investigations list
  async function renderHistory() {
    setPage("Investigations", [el("a", { class: "btn btn-primary btn-small", href: "#/new" }, "New investigation")]);
    loading();
    const { investigations: list } = await call("/api/investigations");
    if (!list.length) {
      put(emptyState("Nothing here yet", "Every log you investigate is saved here for your account."));
      return;
    }
    put(el("section", { class: "panel" }, el("div", { class: "table-wrap" }, el("table", { class: "t" },
      el("thead", {}, el("tr", {}, el("th", {}, "Log"), el("th", { class: "hide-sm" }, "Run"), el("th", { class: "num" }, "Requests"),
        el("th", { class: "num" }, "Attack requests"), el("th", { class: "num hide-sm" }, "Flagged visitors"), el("th", { class: "hide-sm" }, "Mode"), el("th", {}, ""))),
      el("tbody", {}, list.map((it) => {
        const del = deleteButton(it.id, () => route());
        const tr = linkRow(`#/inv/${it.id}`,
          el("td", {}, el("div", { class: "logcell" },
            Falcon.make({ size: 26, state: (it.attack_requests || it.sessions_flagged) ? "threat" : "safe", label: (it.attack_requests || it.sessions_flagged) ? "Attacks found" : "Clean" }),
            el("div", {}, el("div", {}, it.filename || "log"), el("div", { class: "small muted" }, it.format || "")))),
          el("td", { class: "hide-sm nowrap small" }, fmtDate(it.created_at)),
          el("td", { class: "num" }, num(it.parsed)),
          el("td", { class: "num" }, num(it.attack_requests)),
          el("td", { class: "num hide-sm" }, `${num(it.sessions_flagged)} / ${num(it.sessions_total)}`),
          el("td", { class: "hide-sm" }, nice(it.mode)),
          el("td", { class: "num" }, del));
        return tr;
      }))))));
  }
  function deleteButton(id, after) {
    // Two clicks instead of a browser dialog: "Delete", then "Confirm".
    const b = el("button", { class: "btn btn-danger btn-small", type: "button" }, "Delete");
    let armed = false;
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!armed) { armed = true; b.textContent = "Confirm delete"; setTimeout(() => { armed = false; b.textContent = "Delete"; }, 4000); return; }
      b.disabled = true;
      try { await call(`/api/investigations/${id}`, { method: "DELETE" }); after(); }
      catch (err) { b.textContent = "Failed"; }
    });
    return b;
  }

  // ---------------------------------------------------------------- one investigation
  // One investigation is split into sections, picked from the sidebar: Summary, Visitors,
  // Attack requests, Fixes and rules. The result is fetched once and kept while you switch.
  let current = null;            // { key, data, saved }
  const SECTIONS = [["summary", "Summary"], ["visitors", "Visitors"], ["requests", "Attack requests"], ["fixes", "Fixes and rules"]];
  /** Tabs at the top of one investigation, with counts. */
  function caseTabs(key, section, counts) {
    return el("nav", { class: "case-tabs", "aria-label": "This investigation" }, SECTIONS.map(([id, label]) => {
      const a = el("a", { href: `#/inv/${key}/${id}` }, label, counts[id] != null ? el("span", { class: "count" }, num(counts[id])) : null);
      if (id === section) a.setAttribute("aria-current", "page");
      return a;
    }));
  }

  // "Needs a look": the detector's score is between REVIEW_FROM and the mode's threshold, so the request is not
  // called an attack, but the model was close. A review mark only; detection and verdicts are not changed.
  const REVIEW_FROM = 0.5;
  let reviewTo = 0.7;
  const needsLook = (r) => !r.is_attack && r.attack_prob != null && r.attack_prob >= REVIEW_FROM && r.attack_prob < reviewTo;

  async function renderInvestigation(key, section) {
    if (!current || current.key !== String(key)) {
      if (key === "file") { location.hash = "#/new"; return; }
      setPage("Investigation");
      loading();
      current = { key: String(key), data: await call(`/api/investigations/${Number(key)}`), saved: true };
    }
    showInvestigation(current, section);
  }

  function showInvestigation({ key, data, saved }, section) {
    const exportBtn = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Save as JSON");
    exportBtn.addEventListener("click", () => download(data));
    setPage(data.filename || "Investigation", [exportBtn, saved ? deleteButton(data.id, () => { current = null; location.hash = "#/history"; }) : null].filter(Boolean));

    const sessions = data.sessions || [];
    reviewTo = Number(data.threshold) || 0.7;
    const timeline = sessions.flatMap((s) => (s.timeline || []).map((t) => ({ ...t, ip: s.ip })));
    const attacks = timeline.filter((t) => t.is_attack).length;
    const toReview = timeline.filter(needsLook).length;
    const payload = timeline.filter((t) => t.label === "attack").length;
    const blocked = sessions.filter((s) => s.action === "block" && s.risk_score > 0).length;
    const flaggedCount = data.sessions_flagged ?? sessions.filter((x) => x.risk_score > 0).length;
    const fixList = mergedFixes(sessions), ruleLines = mergedRules(sessions);

    Falcon.favicon(attacks > 0 ? "threat" : "safe");
    const banners = [
      caseTabs(key, section, { visitors: flaggedCount, requests: attacks, fixes: fixList.length }),
      !saved ? el("div", { class: "notice warn banner" }, "Opened from a file. This result is not saved to your account.") : null,
      data.sample ? el("div", { class: "notice warn banner" }, "Sample data for the interface only. Do not quote these numbers.") : null,
    ];
    const sectionHead = (title, sub) => el("div", { class: "section-head" }, el("h2", {}, title), sub ? el("p", { class: "muted" }, sub) : null);

    if (section === "visitors") return put(...banners, visitorsPanel(sessions));
    if (section === "requests") {
      return put(...banners, sectionHead("Attack requests", "Every request in the log, with the visitor it came from. Untick the box to see normal requests too."),
        el("section", { class: "panel" }, timelineTable({ timeline: [...timeline].sort((x, y) => String(x.timestamp).localeCompare(String(y.timestamp))) }, { showIp: true })));
    }
    if (section === "fixes") {
      return put(...banners, sectionHead("Fixes and rules", "What to change in the site, and WAF rules for every flagged visitor in this log."),
        el("div", { class: "grid grid-2" },
          el("section", { class: "panel" }, fixList.length ? fixes({ fixes: fixList }) : el("p", { class: "muted" }, "No fixes needed: no attack found.")),
          el("section", { class: "panel" }, ruleLines.length ? rules({ waf_rules: ruleLines }) : el("p", { class: "muted" }, "No WAF rules: no visitor to block."))));
    }

    // Summary
    const types = {};
    for (const t of timeline) if (t.is_attack && t.attack_type) types[t.attack_type] = (types[t.attack_type] || 0) + 1;
    const levels = Object.fromEntries(LEVELS.map((l) => [l, sessions.filter((s) => s.risk_level === l).length]));
    const stages = Object.fromEntries(STAGES.map((st) => [st, sessions.filter((s) => (s.stage_path || []).includes(st)).length]));
    const top = sessions.filter((s) => s.risk_score > 0).sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);
    put(...banners,
      verdict(attacks, flaggedCount, null),
      el("section", { class: "kpis summary", "aria-label": "Summary" },
        kpi("Requests read", num(data.parsed ?? timeline.length), `${num(data.skipped || 0)} lines skipped, ${data.format || "unknown format"}`),
        kpi("Visitors flagged", `${num(flaggedCount)} / ${num(data.sessions_total ?? sessions.length)}`, levelText(sessions)),
        kpi("Attack requests", num(attacks), `${num(payload)} by payload, ${num(attacks - payload)} by behaviour${toReview ? ` · ${num(toReview)} need a look` : ""}`, "threat"),
        kpi("Suggested blocks", num(blocked), `${num(sessions.filter((s) => s.action === "rate_limit").length)} rate limits`),
        kpi("Mode", nice(data.mode || "sensitive"), `threshold ${data.threshold ?? "–"}${data.seconds ? `, ${data.seconds} s` : ""}`)),
      ...campaignPanels(data.campaigns),
      el("div", { class: "grid grid-2e" },
        panel("Attack types", "attack requests in this log", typeBars(Object.fromEntries(Object.entries(types).sort((a, b) => b[1] - a[1])))),
        panel("How far attackers got", "visitors that reached each stage", stageBars(stages))),
      el("div", { class: "grid grid-2" },
        panel("Visitors by risk", "all visitors in this log", levelStack(levels)),
        panel("Most dangerous visitors", el("a", { href: `#/inv/${key}/visitors` }, "See all visitors"),
          top.length ? el("div", { class: "table-wrap" }, el("table", { class: "t" },
            el("thead", {}, el("tr", {}, el("th", {}, "Visitor"), el("th", {}, "Risk"), el("th", {}, "Action"))),
            el("tbody", {}, top.map((v) => el("tr", {},
              el("td", { class: "ipcell" }, v.ip),
              el("td", {}, el("span", { class: `badge lv-${v.risk_level}` }, `${nice(v.risk_level)} ${v.risk_score}`)),
              el("td", {}, el("span", { class: `badge act-${v.action || "allow"}` }, nice(v.action || "allow")))))))) : el("p", { class: "muted" }, "No flagged visitors."))));
  }

  // Distributed campaigns (backend/app/campaigns.py): many addresses, same browser name, only probe requests.
  // Shown for the admin; the per-visitor verdicts are not changed by them.
  function campaignPanels(list) {
    return (list || []).map((c) => {
      const rules = c.addresses.map((ip) => `deny ${ip};`).join("\n");
      const copy = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Copy block rules");
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(rules); copy.textContent = "Copied"; } catch { copy.textContent = "Copy failed"; }
        setTimeout(() => { copy.textContent = "Copy block rules"; }, 2000);
      });
      const open = el("details", { class: "campaign-ips" }, el("summary", {}, `Show the ${num(c.addresses.length)} addresses`),
        el("pre", { class: "rules" }, c.addresses.join("\n")));
      return el("section", { class: "panel campaign" },
        el("div", { class: "panel-head" }, el("h2", {}, "Possible distributed campaign"), copy),
        el("p", { class: "campaign-lead" },
          el("strong", {}, `${num(c.addresses.length)} addresses`), " sent only probe requests with the same browser name. ",
          "Each one alone looks like a mistyped link; together they are one tool."),
        el("dl", { class: "facts" },
          el("dt", {}, "Browser name"), el("dd", { class: "mono small" }, c.user_agent),
          el("dt", {}, "Requests"), el("dd", {}, `${num(c.requests)} from ${num(c.visitors)} visitors`),
          el("dt", {}, "Answers"), el("dd", {}, Object.entries(c.statuses || {}).map(([k, v]) => `${k} × ${num(v)}`).join(", ")),
          el("dt", {}, "Examples"), el("dd", { class: "mono small" }, (c.examples || []).join("  "))),
        open,
        el("p", { class: "note" }, "Shown for review. Each visitor's risk and action in this log are not changed by this card."));
    });
  }

  function visitorsPanel(sessions) {
    let openId = null;
    const search = el("input", { class: "search", type: "search", placeholder: "Filter by address, type or stage", "aria-label": "Filter visitors" });
    const flagged = el("input", { type: "checkbox" });
    flagged.checked = true;
    const tbody = el("tbody");
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      const list = sessions.filter((s) => (!flagged.checked || s.risk_score > 0) && (!q || haystack(s).includes(q)))
        .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0) || (b.requests || 0) - (a.requests || 0));
      if (!list.length) {
        tbody.replaceChildren(el("tr", {}, el("td", { colspan: 7, class: "muted", style: "padding:28px 0;text-align:center" },
          sessions.length ? (flagged.checked && !q ? "No visitor was flagged in this log. Untick “Flagged only” to see everyone." : "No visitor matches the filter.") : "No requests in this log.")));
        return;
      }
      const rows = [];
      for (const s of list) {
        const open = s.session === openId;
        const what = [...new Set([...(s.attack_types || []), ...(s.behaviours || [])])];
        const tr = el("tr", { class: `s link${open ? " open" : ""}`, tabindex: 0, "aria-expanded": String(open) },
          el("td", {}, el("span", { class: `badge lv-${s.risk_level}` }, `${nice(s.risk_level)} ${s.risk_score}`)),
          el("td", { class: "ipcell" }, s.ip, s.trusted ? el("div", { class: "small", style: "color:var(--clean);margin-top:2px", title: "On your trusted list: shown, never blocked" }, "Trusted") : null,
            s.campaign ? el("div", { class: "small", style: "color:var(--threat);margin-top:2px", title: "Part of a possible distributed campaign (see Summary)" }, `Campaign ${s.campaign}`) : null,
            (() => { const n = (s.timeline || []).filter(needsLook).length; return n ? el("div", { class: "small", style: "color:var(--warn);margin-top:2px", title: "Requests the detector was close to calling attacks" }, `${n} to review`) : null; })()),
          el("td", { class: "what" }, what.length ? what.map((w) => el("span", { class: "chip" }, nice(w))) : el("span", { class: "muted small" }, "Normal browsing")),
          el("td", { class: "num" }, num(s.requests)),
          el("td", { class: "hide-sm" }, s.stage ? nice(s.stage) : "–"),
          el("td", {}, el("span", { class: `badge act-${s.action || "allow"}` }, nice(s.action || "allow"))));
        const toggle = () => { openId = open ? null : s.session; draw(); };
        tr.addEventListener("click", toggle);
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
        rows.push(tr);
        if (open) rows.push(el("tr", { class: "open" }, el("td", { colspan: 6, class: "detail" }, sessionDetail(s))));
      }
      tbody.replaceChildren(...rows);
    };
    search.addEventListener("input", draw);
    flagged.addEventListener("change", draw);
    draw();
    return el("section", { class: "panel" },
      el("div", { class: "toolbar" }, el("h2", {}, "Visitors"), el("span", { class: "grow" }), search, el("label", { class: "check" }, flagged, "Flagged only")),
      el("div", { class: "table-wrap" }, el("table", { class: "t sessions" },
        el("colgroup", {}, el("col", { class: "c-risk" }), el("col", { class: "c-ip" }), el("col"), el("col", { class: "c-req" }), el("col", { class: "c-stage" }), el("col", { class: "c-act" })),
        el("thead", {}, el("tr", {}, ["Risk", "Visitor", "What happened", "Requests", "Stage", "Action"].map((h, i) => el("th", { class: i === 3 ? "num" : null }, h)))),
        tbody)),
      el("p", { class: "note" }, "A visitor is one address and browser, with gaps under 30 minutes. Select a row for the reasons, the stage and that visitor's requests."));
  }
  function mergedFixes(sessions) {
    const seen = new Map();
    for (const s of sessions) for (const f of s.fixes || []) {
      const m = f.matches?.[0];
      if (m && !seen.has(m.title)) seen.set(m.title, f);
    }
    return [...seen.values()];
  }
  function mergedRules(sessions) {
    return [...new Set(sessions.flatMap((s) => s.waf_rules || []))];
  }
  function haystack(s) {
    return [s.ip, s.risk_level, s.stage, s.action, s.campaign ? "campaign" : "", ...(s.behaviours || []), ...(s.attack_types || [])]
      .concat((s.attack_types || []).map(nice)).map((x) => String(x || "").toLowerCase()).join(" ");
  }
  function levelText(sessions) {
    const parts = LEVELS.filter((l) => l !== "none").map((l) => [l, sessions.filter((s) => s.risk_level === l).length]).filter(([, n]) => n);
    return parts.length ? parts.map(([l, n]) => `${n} ${l}`).join(", ") : "none flagged";
  }

  function sessionDetail(s) {
    const left = el("div", {},
      el("h3", {}, "Why"),
      s.reasons?.length ? el("ul", { class: "reasons" }, s.reasons.map((r) => el("li", {}, r))) : el("p", { class: "muted" }, "Nothing suspicious."),
      s.login_after_failures ? el("div", { class: "notice error", style: "margin-top:10px" }, "A login succeeded after the failed attempts. Check this account.") : null,
      el("h3", {}, "Attack stage"), stageBar(s),
      el("h3", {}, "Steps and likely next step"), steps(s));
    const right = el("div", {},
      el("h3", {}, "Suggested action"),
      el("p", {}, el("span", { class: `badge act-${s.action || "allow"}` }, nice(s.action || "allow")), " ", el("span", { class: "muted small" }, s.action_reason || "")),
      fixes(s));
    return el("div", { class: "detail" }, el("div", { class: "detail-grid" }, left, right),
      el("h3", {}, `Requests, ${num((s.timeline || []).length)}`), timelineTable(s));
  }
  function stageBar(s) {
    const seen = new Set(s.stage_path || []);
    if (!seen.size) return el("p", { class: "muted" }, "No attack stage reached.");
    return el("div", {},
      el("div", { class: "stages" }, STAGES.map((st) => el("span", { class: st === s.stage ? "top" : seen.has(st) ? "seen" : "" }, nice(st)))),
      el("p", { class: "note" }, `Order seen: ${s.stage_path.map(nice).join(", then ")}.`));
  }
  function steps(s) {
    const seen = s.steps || [], next = s.next_steps || [];
    if (!seen.length && !next.length) return el("p", { class: "muted" }, "No attack steps.");
    return el("div", {},
      seen.length ? el("p", {}, "Seen: ", seen.map((x) => el("span", { class: "chip" }, nice(x)))) : null,
      next.length ? el("p", { style: "margin-top:6px" }, "Likely next: ", next.map(([st, p]) => el("span", { class: "chip" }, `${nice(st)} ${Math.round(p * 100)}%`))) : null,
      el("p", { class: "note" }, "The next-step guess comes from lab attacks and could not be measured on real attackers."));
  }
  function fixes(s) {
    const list = (s.fixes || []).filter((f) => f.matches?.length);
    if (!list.length) return null;
    return el("div", {}, el("h3", {}, "How to fix"), list.map((f) => {
      const m = f.matches[0];
      return el("div", { class: "fix" }, el("strong", {}, `${nice(f.step)}: ${m.title}`),
        el("div", { class: "meta" }, [m.owasp, m.cwe].filter(Boolean).join(", ")),
        el("ul", {}, (m.fix || []).map((x) => el("li", {}, x))),
        el("div", { class: "meta" }, `Source: ${m.source}`));
    }));
  }
  function rules(s) {
    const r = s.waf_rules || [];
    if (!r.length) return null;
    const text = r.join("\n");
    const copy = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Copy");
    copy.addEventListener("click", async (e) => {
      e.stopPropagation();
      try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; } catch { copy.textContent = "Copy failed"; }
      setTimeout(() => { copy.textContent = "Copy"; }, 1500);
    });
    return el("div", {}, el("div", { class: "rules-head" }, el("h3", {}, "WAF rules"), copy), el("pre", { class: "rules" }, text),
      el("p", { class: "note" }, "Review before use. Lines starting with # are Nginx settings or advice."));
  }
  function timelineTable(s, { showIp = false } = {}) {
    const t = s.timeline || [];
    const only = el("input", { type: "checkbox" });
    only.checked = showIp;
    const look = el("input", { type: "checkbox" });
    const nLook = t.filter(needsLook).length;
    const tbody = el("tbody");
    const fill = () => tbody.replaceChildren(...t.filter((r) => look.checked ? needsLook(r) : (!only.checked || r.is_attack)).slice(0, 500).map((r) =>
      el("tr", { class: r.is_attack ? "attack" : "" },
        el("td", { class: "nowrap" }, fmtTime(r.timestamp).slice(11) || "–"),
        showIp ? el("td", { class: "ipcell" }, r.ip || "–") : null,
        el("td", { class: "req" }, `${r.method} ${r.path}`, r.body ? el("div", { class: "muted" }, `body: ${r.body}`) : null),
        el("td", {}, r.status ?? "–"),
        el("td", { class: "num" }, r.attack_prob == null ? "–" : Number(r.attack_prob).toFixed(2)),
        el("td", {}, r.attack_type ? nice(r.attack_type) : r.is_attack ? "Attack" : "–",
          r.reasons?.length ? el("div", { class: "muted small" }, r.reasons.join("; ")) : null),
        el("td", { class: "hide-sm" },
          needsLook(r) ? el("span", { class: "chip look", title: "The detector was close to calling this an attack. A review mark only; it never changes detection." }, "Needs a look") : null,
          r.unusual ? el("span", { class: "chip", title: "Rare in this log. A review mark only; it never changes detection." }, "Unusual") : null))));
    only.addEventListener("change", () => { if (only.checked) look.checked = false; fill(); });
    look.addEventListener("change", () => { if (look.checked) only.checked = false; fill(); });
    look.addEventListener("click", (e) => e.stopPropagation());
    only.addEventListener("click", (e) => e.stopPropagation());
    fill();
    return el("div", {},
      el("div", { class: "checks" }, el("label", { class: "check" }, only, "Attack requests only"),
        nLook ? el("label", { class: "check" }, look, `Needs a look only (${num(nLook)})`) : null),
      el("div", { class: "table-wrap" }, el("table", { class: "t timeline" },
        el("thead", {}, el("tr", {}, ["Time", showIp ? "Visitor" : null, "Request", "Status", "Score", "Type and why", "Review"].filter(Boolean)
          .map((h) => el("th", { class: h === "Score" ? "num" : h === "Review" ? "hide-sm" : null }, h)))),
        tbody)),
      t.length > 500 ? el("p", { class: "note" }, `Showing the first 500 of ${num(t.length)} requests. The saved JSON has all of them.`) : null,
      el("p", { class: "note" }, `Score is the detector's attack probability. A request is an attack by payload when the score reaches the mode's threshold, or by behaviour from the whole visit. "Needs a look": score from ${REVIEW_FROM} up to the threshold.`));
  }
  function download(data) {
    const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: "application/json" })),
      download: `${String(data.filename || "log").replace(/\.[^.]+$/, "")}-investigation.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ---------------------------------------------------------------- account
  // ---------------------------------------------------------------- sidebar data (counts, recent logs)
  let sideList = null;           // the latest /api/investigations answer
  async function refreshSide() {
    try { sideList = (await call("/api/investigations")).investigations; } catch { return; }
    const visitors = attackerList(sideList);
    const ci = $("#cnt-inv"), ca = $("#cnt-att");
    ci.hidden = !sideList.length; ci.textContent = num(sideList.length);
    ca.hidden = !visitors.length; ca.textContent = num(visitors.length);
    drawNotifications();
    const box = $("#side-recent");
    box.hidden = !sideList.length;
    const here = (location.hash.split("/")[2] || "");
    box.replaceChildren(el("div", { class: "side-label side-label-link" }, el("span", { class: "lbl" }, "Recent"),
        el("a", { class: "lbl", href: "#/recent" }, "See all")),
      ...sideList.slice(0, 4).map((it) => {
        const bad = (it.attack_requests || it.sessions_flagged) > 0;
        const a = el("a", { href: `#/inv/${it.id}`, title: it.filename || "log" },
          el("span", { class: `rdot ${bad ? "bad" : "ok"}`, "aria-hidden": "true" }),
          el("span", { class: "rname" }, it.filename || "log"),
          el("span", { class: `rnum ${bad ? "bad" : ""}` }, bad ? num(it.attack_requests) : "clean"));
        if (String(it.id) === here) a.setAttribute("aria-current", "page");
        return a;
      }));
  }

  /** Every flagged visitor over all saved logs: highest risk seen, how many logs, latest log. */
  function attackerList(items) {
    const map = new Map();
    for (const it of items) {
      for (const v of it.flagged_visitors || it.top_sessions || []) {
        if (!v.ip) continue;
        const a = map.get(v.ip) || { ip: v.ip, risk_score: -1, risk_level: "none", action: "allow", logs: 0, last: it, types: new Set() };
        a.logs += 1;
        (v.attack_types || []).forEach((t) => a.types.add(t));
        if ((v.risk_score || 0) > a.risk_score) Object.assign(a, { risk_score: v.risk_score || 0, risk_level: v.risk_level, action: v.action || "allow" });
        map.set(v.ip, a);
      }
    }
    return [...map.values()].sort((x, y) => y.risk_score - x.risk_score || y.logs - x.logs);
  }

  // ---------------------------------------------------------------- recent: one card per log, by day
  async function renderRecent() {
    setPage("Recent", [el("a", { class: "btn btn-primary btn-small", href: "#/new" }, "New investigation")]);
    loading();
    const items = (await call("/api/investigations")).investigations;
    if (!items.length) { put(emptyState("Nothing here yet", "Every log you investigate shows up here, newest first.")); return; }
    const day = (sec) => { const d = new Date(sec * 1000); d.setHours(0, 0, 0, 0); return d.getTime(); };
    const today = day(Date.now() / 1000), dayMs = 86400000;
    const label = (t) => t === today ? "Today" : t === today - dayMs ? "Yesterday"
      : new Date(t).toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" });
    const groups = new Map();
    for (const it of items) { const k = day(it.created_at); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(it); }
    put(...[...groups].map(([k, list]) => el("section", { class: "day" },
      el("h2", { class: "day-title" }, label(k), el("span", { class: "muted" }, `${list.length} log${list.length > 1 ? "s" : ""}`)),
      el("div", { class: "log-cards" }, list.map(logCard)))));
  }
  function logCard(it) {
    const bad = (it.attack_requests || it.sessions_flagged) > 0;
    const lv = it.levels || {};
    const total = LEVELS.reduce((n, l) => n + (lv[l] || 0), 0) || 1;
    const types = Object.keys(it.types || {}).slice(0, 3);
    const a = el("a", { class: `log-card ${bad ? "bad" : "good"}`, href: `#/inv/${it.id}` },
      el("div", { class: "lc-top" },
        Falcon.make({ size: 40, state: bad ? "threat" : "safe", label: bad ? "Attacks found" : "Clean" }),
        el("div", { class: "lc-name" }, el("strong", {}, it.filename || "log"),
          el("span", { class: "small muted" }, `${new Date(it.created_at * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })} · ${it.format || "log"} · ${nice(it.mode || "sensitive")}`))),
      el("div", { class: "lc-stats" },
        el("div", {}, el("b", { class: bad ? "threat" : "" }, num(it.attack_requests || 0)), el("span", {}, "attack requests")),
        el("div", {}, el("b", {}, `${num(it.sessions_flagged || 0)}/${num(it.sessions_total || 0)}`), el("span", {}, "visitors flagged")),
        el("div", {}, el("b", {}, num(it.parsed || 0)), el("span", {}, "requests"))),
      el("div", { class: "lc-risk", "aria-label": "Visitors by risk" }, LEVELS.filter((l) => lv[l]).map((l) =>
        el("i", { class: `lv-bg-${l}`, style: `flex:${lv[l] / total}`, title: `${nice(l)} ${lv[l]}` }))),
      el("div", { class: "lc-tags" }, types.length ? types.map((t) => el("span", { class: "chip" }, nice(t))) : el("span", { class: "chip ok" }, "No attacks")));
    return a;
  }

  // ---------------------------------------------------------------- notifications (bell in the top bar)
  // Built from your saved investigations: finished logs, critical visitors and visitors that came back.
  // Which ones you have read is remembered in this browser only.
  let readUntil = 0;
  try { readUntil = Number(localStorage.getItem("aai-notif-read") || 0); } catch { /* private mode */ }
  function notifications(limit = 30) {
    const out = [];
    for (const it of sideList || []) {
      const bad = (it.attack_requests || it.sessions_flagged) > 0;
      out.push({ time: it.created_at, tone: bad ? "bad" : "good", href: `#/inv/${it.id}`,
        title: bad ? `${num(it.attack_requests)} attack requests in ${it.filename || "a log"}` : `${it.filename || "A log"} looks clean`,
        text: bad ? `${num(it.sessions_flagged)} suspicious visitors. Open the case.` : "No attack found." });
      for (const v of (it.flagged_visitors || it.top_sessions || []).filter((x) => x.risk_level === "critical").slice(0, 3)) {
        out.push({ time: it.created_at + 0.001, tone: "bad", href: `#/inv/${it.id}/visitors`,
          title: `Critical visitor ${v.ip}`, text: `In ${it.filename || "a log"}. Suggested action: ${nice(v.action || "block")}.` });
      }
    }
    for (const a of attackerList(sideList || []).filter((x) => x.logs > 1).slice(0, 5)) {
      out.push({ time: a.last.created_at + 0.002, tone: "warn", href: "#/attackers",
        title: `${a.ip} came back`, text: `Seen in ${a.logs} of your logs. Consider blocking it.` });
    }
    return out.sort((x, y) => y.time - x.time).slice(0, limit);
  }
  function notifItem(n, { onClick } = {}) {
    const a = el("a", { class: `notif-item ${n.tone}${n.time > readUntil ? " unread" : ""}`, href: n.href },
      el("span", { class: "nd", "aria-hidden": "true" }),
      el("span", { class: "nt" }, el("strong", {}, n.title), el("span", {}, n.text), el("small", {}, fmtDate(n.time))));
    if (onClick) a.addEventListener("click", onClick);
    return a;
  }
  const NOTIF_FILTERS = { all: ["All", () => true], unread: ["Unread", (n) => n.time > readUntil],
    threats: ["Threats", (n) => n.tone !== "good"], clean: ["Clean logs", (n) => n.tone === "good"] };
  async function renderNotifications(filter) {
    if (!NOTIF_FILTERS[filter]) filter = "all";
    const read = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Mark all as read");
    read.addEventListener("click", () => { markAllRead(); renderNotifications(filter); });
    setPage("Notifications", [read]);
    loading();
    sideList = (await call("/api/investigations")).investigations;
    const all = notifications(500);
    const tabs = el("nav", { class: "case-tabs", "aria-label": "Filter notifications" }, Object.entries(NOTIF_FILTERS).map(([k, [label, keep]]) =>
      el("a", { href: `#/notifications/${k}`, "aria-current": k === filter ? "page" : null },
        label, el("span", { class: "count" }, num(all.filter(keep).length)))));
    const list = all.filter(NOTIF_FILTERS[filter][1]);
    if (!list.length) {
      put(tabs, emptyState(filter === "unread" ? "All caught up" : "No notifications yet",
        filter === "unread" ? "You have read everything. New results show up here." : "Results of your investigations show up here."));
      return;
    }
    const day = (sec) => { const d = new Date(sec * 1000); d.setHours(0, 0, 0, 0); return d.getTime(); };
    const today = day(Date.now() / 1000), dayMs = 86400000;
    const label = (t) => t === today ? "Today" : t === today - dayMs ? "Yesterday"
      : new Date(t).toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" });
    const groups = new Map();
    for (const n of list) { const k = day(n.time); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n); }
    put(tabs, ...[...groups].map(([k, items]) => el("section", { class: "day" },
      el("h2", { class: "day-title" }, label(k), el("span", { class: "muted" }, `${items.length}`)),
      el("div", { class: "panel notif-page" }, items.map((n) => notifItem(n))))));
  }
  function drawNotifications() {
    const list = notifications();
    const unread = list.filter((n) => n.time > readUntil).length;
    const badge = $("#bell-count");
    badge.hidden = !unread; badge.textContent = unread > 9 ? "9+" : String(unread);
    $("#bell").setAttribute("aria-label", unread ? `Notifications, ${unread} unread` : "Notifications");
    const cn = $("#cnt-notif");
    if (cn) { cn.hidden = !unread; cn.textContent = num(unread); }
    $("#notif-list").replaceChildren(...(list.length ? list.slice(0, 8).map((n) => notifItem(n, { onClick: () => toggleNotif(false) }))
      : [el("p", { class: "muted small notif-empty" }, "Nothing yet. Results of your investigations show up here.")]));
  }
  function toggleNotif(open) {
    const panel = $("#notif-panel");
    panel.hidden = !open;
    $("#bell").setAttribute("aria-expanded", String(open));
  }
  function markAllRead() {
    readUntil = Date.now() / 1000;
    try { localStorage.setItem("aai-notif-read", String(readUntil)); } catch { /* private mode */ }
    drawNotifications();
  }
  /** Desktop alert when an investigation finishes while you are in another tab. */
  function desktopAlert(title, body) {
    try { if (document.hidden && "Notification" in window && Notification.permission === "granted") new Notification(title, { body, icon: "/static/img/icon.svg" }); }
    catch { /* not supported */ }
  }

  // ---------------------------------------------------------------- attackers and block list
  const BLOCK_FORMATS = {
    nginx: ["Nginx", (ip) => `deny ${ip};`],
    apache: ["Apache", (ip) => `Require not ip ${ip}`],
    iptables: ["iptables", (ip) => `iptables -A INPUT -s ${ip} -j DROP`],
    plain: ["Plain list", (ip) => ip],
  };
  async function renderAttackers() {
    setPage("Attackers");
    loading();
    const list = attackerList(sideList || (await call("/api/investigations")).investigations);
    if (!list.length) { put(emptyState("No attackers yet", "Visitors the falcon flags in your logs are gathered here, with a block list you can copy.")); return; }
    const blocks = list.filter((a) => a.action === "block");
    let fmt = "nginx";
    const out = el("pre", { class: "codebox" });
    const fill = () => { out.textContent = blocks.map((a) => BLOCK_FORMATS[fmt][1](a.ip)).join("\n") || "No visitor needs a block."; };
    const fmts = el("div", { class: "seg small", role: "radiogroup", "aria-label": "Block list format" }, Object.entries(BLOCK_FORMATS).map(([k, [name]]) => {
      const b = el("button", { type: "button", role: "radio", "aria-checked": String(k === fmt) }, name);
      b.addEventListener("click", () => { fmt = k; for (const x of fmts.children) x.setAttribute("aria-checked", String(x === b)); fill(); });
      return b;
    }));
    const copy = el("button", { class: "btn btn-primary btn-small", type: "button" }, "Copy block list");
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(out.textContent); copy.textContent = "Copied"; }
      catch { copy.textContent = "Select and copy by hand"; }
      setTimeout(() => { copy.textContent = "Copy block list"; }, 1800);
    });
    fill();
    put(el("section", { class: "kpis four" },
        kpi("Flagged visitors", num(list.length), `over ${num((sideList || []).length)} logs`),
        kpi("To block", num(blocks.length), "action: block", "threat"),
        kpi("To rate-limit", num(list.filter((a) => a.action === "rate_limit").length), "action: rate limit"),
        kpi("Seen in 2+ logs", num(list.filter((a) => a.logs > 1).length), "came back")),
      el("div", { class: "grid grid-2" },
        panel("All flagged visitors", "highest risk seen in any log",
          el("div", { class: "table-wrap" }, el("table", { class: "t" },
            el("thead", {}, el("tr", {}, el("th", {}, "Visitor"), el("th", {}, "Risk"), el("th", {}, "Action"), el("th", { class: "hide-sm" }, "Attack types"), el("th", { class: "num" }, "Logs"))),
            el("tbody", {}, list.map((a) => linkRow(`#/inv/${a.last.id}/visitors`,
              el("td", { class: "ipcell" }, a.ip),
              el("td", {}, el("span", { class: `badge lv-${a.risk_level}` }, `${nice(a.risk_level)} ${a.risk_score}`)),
              el("td", {}, el("span", { class: `badge act-${a.action}` }, nice(a.action))),
              el("td", { class: "hide-sm small muted" }, [...a.types].map(nice).join(", ") || "behaviour"),
              el("td", { class: "num" }, a.logs))))))),
        el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Block list"), copy),
          el("p", { class: "muted small" }, `${num(blocks.length)} visitors the models say to block. Paste the lines into your server's config.`),
          fmts, out)));
  }

  // ---------------------------------------------------------------- search (sidebar box)
  async function renderSearch() {
    const q = $("#side-q").value.trim().toLowerCase();
    setPage(q ? `Search: ${q}` : "Search");
    const items = sideList || (await call("/api/investigations")).investigations;
    if (!q) { put(emptyState("Search your logs", "Type a log name or a visitor address in the box on the left.")); return; }
    const logs = items.filter((it) => (it.filename || "").toLowerCase().includes(q));
    const ips = attackerList(items).filter((a) => a.ip.toLowerCase().includes(q));
    if (!logs.length && !ips.length) { put(emptyState("Nothing found", `No log name or flagged visitor matches "${q}".`)); return; }
    put(el("div", { class: "grid grid-2" },
      panel("Logs", `${num(logs.length)} found`, logs.length ? recentList(logs) : el("p", { class: "muted" }, "No log name matches.")),
      panel("Flagged visitors", `${num(ips.length)} found`, ips.length ? el("div", { class: "table-wrap" }, el("table", { class: "t" },
        el("tbody", {}, ips.map((a) => linkRow(`#/inv/${a.last.id}/visitors`,
          el("td", { class: "ipcell" }, a.ip),
          el("td", {}, el("span", { class: `badge lv-${a.risk_level}` }, `${nice(a.risk_level)} ${a.risk_score}`)),
          el("td", { class: "num small muted" }, `${a.logs} log${a.logs > 1 ? "s" : ""}`)))))) : el("p", { class: "muted" }, "No flagged visitor matches."))));
  }

  async function renderAccount() {
    setPage("Account");
    loading();
    const info = await call("/me");
    const cur = el("input", { class: "input", type: "password", id: "a-cur", autocomplete: "current-password", required: true });
    const nw = el("input", { class: "input", type: "password", id: "a-new", autocomplete: "new-password", required: true });
    const nw2 = el("input", { class: "input", type: "password", id: "a-new2", autocomplete: "new-password", required: true });
    const code = el("input", { class: "input code", id: "a-code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 7, required: true });
    const msg = el("div", { class: "notice", role: "alert", hidden: true });
    const btn = el("button", { class: "btn btn-primary", type: "submit" }, "Change password");
    const send = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Send code to my e-mail");
    send.addEventListener("click", async () => {
      send.disabled = true;
      try {
        const r = await api("/api/account/code", { method: "POST" });
        msg.className = "notice ok"; msg.textContent = `Code sent to ${r.sent_to}. It works for 10 minutes.`; msg.hidden = false;
        code.otpFocus();
      } catch (err) { msg.className = "notice error"; msg.textContent = err.message; msg.hidden = false; }
      setTimeout(() => { send.disabled = false; }, 30000);
    });
    const form = el("form", { class: "form", novalidate: true },
      el("div", { class: "field" }, el("label", { for: "a-cur" }, "Current password"), cur),
      el("div", { class: "field" },
        el("div", { class: "field-row" },
          el("div", { class: "field" }, el("label", { for: "a-new" }, "New password"), nw),
          el("div", { class: "field" }, el("label", { for: "a-new2" }, "Repeat it"), nw2)),
        passwordMeter(nw, () => [info.username, info.email || ""])),
      el("div", { class: "field" }, el("div", { class: "code-row" }, el("label", { for: "a-code" }, "Code from your e-mail"), send), code),
      btn, msg,
      el("p", { class: "note" }, "Changing it logs out every session of this account, and we e-mail you a notice."));
    otp(code);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.hidden = true;
      if (nw.value !== nw2.value) { msg.className = "notice error"; msg.textContent = "The two new passwords are different."; msg.hidden = false; return; }
      btn.disabled = true;
      try {
        await api("/api/account/password", { method: "POST", json: { current_password: cur.value, new_password: nw.value, code: code.value } });
        cur.value = nw.value = nw2.value = "";
        msg.className = "notice ok"; msg.textContent = "Password changed. Log in again with the new password."; msg.hidden = false;
        setTimeout(() => location.replace("/login"), 1800);
      } catch (err) { msg.className = "notice error"; msg.textContent = err.message; msg.hidden = false; btn.disabled = false; }
      finally { code.otpReset(); }
    });
    put(el("div", { class: "account" },
      el("div", { class: "account-col" },
      el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Your account")),
        el("dl", { class: "facts" },
          el("dt", {}, "User name"), el("dd", {}, info.username),
          el("dt", {}, "E-mail"), el("dd", {}, info.email || "None yet"),
          el("dt", {}, "Member since"), el("dd", {}, fmtDate(info.created_at)),
          el("dt", {}, "Last login"), el("dd", {}, fmtDate(info.last_login)),
          el("dt", {}, "Two-step login"), el("dd", {}, "On, codes by e-mail")),
        el("p", { class: "note", style: "margin-top:18px" }, "Every login needs your password and a code sent to this e-mail.")),
      trustedPanel()),
      el("section", { class: "panel password-panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Change password")), form)));
  }

  // Addresses this account trusts (office NAT, own proxy, monitoring). Their visitors are still scored and
  // shown in every investigation, but never blocked or rate-limited (backend/app/trusted.py).
  function trustedPanel() {
    const addr = el("input", { class: "input", id: "t-addr", placeholder: "e.g. 203.0.113.7", maxlength: 64, autocomplete: "off", required: true });
    const note = el("input", { class: "input", id: "t-note", placeholder: "Optional", maxlength: 80, autocomplete: "off" });
    const msg = el("div", { class: "notice", role: "alert", hidden: true });
    const btn = el("button", { class: "btn btn-primary", type: "submit" }, "Add address");
    const list = el("tbody");
    const empty = el("p", { class: "muted small", style: "margin:12px 0 0" }, "No trusted addresses yet.");
    const table = el("div", { class: "table-wrap", style: "margin-top:14px", hidden: true }, el("table", { class: "t" },
      el("thead", {}, el("tr", {}, el("th", {}, "Address"), el("th", {}, "Note"), el("th", {}, ""))), list));
    const say = (cls, text) => { msg.className = `notice ${cls}`; msg.textContent = text; msg.hidden = false; };
    async function load() {
      let items = [];
      try { items = await call("/api/trusted"); } catch (err) { say("error", err.message); }
      table.hidden = !items.length;
      empty.hidden = !!items.length;
      list.replaceChildren(...(items.length ? items.map((t) => {
        const del = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Remove");
        del.addEventListener("click", async () => {
          del.disabled = true;
          try { await call(`/api/trusted/${t.id}`, { method: "DELETE" }); msg.hidden = true; load(); }
          catch (err) { say("error", err.message); del.disabled = false; }
        });
        return el("tr", {}, el("td", { class: "ipcell" }, t.address), el("td", {}, t.note || el("span", { class: "muted small" }, "–")), el("td", {}, del));
      }) : []));
    }
    const form = el("form", { class: "form trusted-form", novalidate: true },
      el("div", { class: "trusted-row" },
        el("div", { class: "field" }, el("label", { for: "t-addr" }, "IP address or network"), addr),
        el("div", { class: "field" }, el("label", { for: "t-note" }, "Note"), note),
        btn),
      msg);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.hidden = true;
      btn.disabled = true;
      try {
        const r = await call("/api/trusted", { method: "POST", json: { address: addr.value, note: note.value } });
        addr.value = note.value = "";
        say("ok", `${r.address} added. It applies to new investigations.`);
        load();
      } catch (err) { say("error", err.message); }
      finally { btn.disabled = false; }
    });
    load();
    return el("section", { class: "panel trusted-panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Trusted addresses")),
      el("p", { class: "note", style: "margin:0 0 14px" }, "Your own addresses, such as an office behind one IP or your reverse proxy: one IP, or a whole network like 203.0.113.0/24. Their visitors are still scored and shown, but never blocked or rate-limited."),
      form, empty, table);
  }

  // ---------------------------------------------------------------- start
  async function boot() {
    try { me = await api("/me"); }
    catch { location.replace("/login"); return; }
    $("#who-name").textContent = me.username;
    $("#avatar").textContent = me.username.slice(0, 1).toUpperCase();
    $("#shell").hidden = false;
    $("#logout").addEventListener("click", async () => {
      try { await api("/logout", { method: "POST" }); } catch { /* already out */ }
      location.replace("/login");
    });
    $("#menu").addEventListener("click", () => {
      $("#side").classList.add("open"); $("#scrim").hidden = false; $("#menu").setAttribute("aria-expanded", "true");
    });
    $("#scrim").addEventListener("click", closeMenu);
    // Collapse the sidebar to icons; remembered in this browser only.
    const setSlim = (on) => {
      $("#shell").classList.toggle("slim", on);
      const b = $("#collapse");
      b.setAttribute("aria-pressed", String(on));
      b.setAttribute("aria-label", on ? "Expand the sidebar" : "Collapse the sidebar");
      b.title = on ? "Expand the sidebar" : "Collapse the sidebar";
      try { localStorage.setItem("aai-slim", on ? "1" : "0"); } catch { /* private mode */ }
    };
    let slim = false;
    try { slim = localStorage.getItem("aai-slim") === "1"; } catch { /* private mode */ }
    setSlim(slim);
    $("#collapse").addEventListener("click", () => setSlim(!$("#shell").classList.contains("slim")));
    api("/health").then((h) => {
      $("#server .dot").className = `dot ${h.model_loaded ? "ok" : "bad"}`;
      $("#server .lbl").textContent = h.model_loaded ? "Models loaded" : "Models not loaded";
    }).catch(() => { $("#server .lbl").textContent = "Server not reachable"; });
    // Notifications: open the panel from the bell; it closes on a click outside or Escape.
    $("#bell").addEventListener("click", (e) => { e.stopPropagation(); toggleNotif($("#notif-panel").hidden); });
    $("#notif-panel").addEventListener("click", (e) => e.stopPropagation());
    $("#notif-read").addEventListener("click", markAllRead);
    $("#notif-all").addEventListener("click", () => toggleNotif(false));
    document.addEventListener("click", () => toggleNotif(false));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") toggleNotif(false); });
    // Search box: results update as you type.
    const q = $("#side-q");
    q.addEventListener("input", () => { if (location.hash.startsWith("#/search")) renderSearch(); else location.hash = "#/search"; });
    q.addEventListener("keydown", (e) => { if (e.key === "Escape") { q.value = ""; q.blur(); location.hash = "#/home"; } });
    $(".top-search").addEventListener("click", () => q.focus());
    // Keyboard shortcuts: / search, N new, G then O/I/A.
    let g = false;
    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) return;
      const k = e.key.toLowerCase();
      if (k === "/") { e.preventDefault(); q.focus(); return; }
      if (g) { g = false; const to = { o: "#/home", i: "#/history", a: "#/attackers" }[k]; if (to) location.hash = to; return; }
      if (k === "g") { g = true; setTimeout(() => { g = false; }, 1200); return; }
      if (k === "n") location.hash = "#/new";
    });
    window.addEventListener("hashchange", route);
    route();
  }
  boot();
})();
