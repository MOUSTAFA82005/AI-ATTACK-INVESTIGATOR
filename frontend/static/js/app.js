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
    document.title = `${title} · AI Attack Investigator`;
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
    const [, name, arg] = (location.hash || "#/home").split("/");
    try {
      if (name === "new") { setNav("new"); return renderNew(); }
      if (name === "history") { setNav("history"); return await renderHistory(); }
      if (name === "inv" && arg) { setNav("history"); return await renderInvestigation(Number(arg)); }
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
      el("div", { class: "grid grid-2e", style: "margin-top:20px" },
        panel("Visitors by risk", "all visitors, all logs", levelStack(s.levels)),
        panel("How far attackers got", "visitors that reached each stage", stageBars(s.stages))),
      el("div", { class: "grid grid-2", style: "margin-top:20px" },
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
        r.addEventListener("change", () => { mode = k; });
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
          return showInvestigation(data, { saved: false });
        } catch (e) { msg.className = "notice error"; msg.textContent = `Could not open the file: ${e.message}`; msg.hidden = false; return; }
      }
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
  async function renderInvestigation(id) {
    setPage("Investigation");
    loading();
    showInvestigation(await call(`/api/investigations/${id}`), { saved: true });
  }

  function showInvestigation(data, { saved }) {
    const exportBtn = el("button", { class: "btn btn-ghost btn-small", type: "button" }, "Save as JSON");
    exportBtn.addEventListener("click", () => download(data));
    setPage(data.filename || "Investigation", [exportBtn, saved ? deleteButton(data.id, () => { location.hash = "#/history"; }) : null].filter(Boolean));

    const sessions = data.sessions || [];
    const timeline = sessions.flatMap((s) => s.timeline || []);
    const attacks = timeline.filter((t) => t.is_attack).length;
    const payload = timeline.filter((t) => t.label === "attack").length;
    const blocked = sessions.filter((s) => s.action === "block" && s.risk_score > 0).length;

    Falcon.favicon(attacks > 0 ? "threat" : "safe");
    let openId = null;
    const search = el("input", { class: "search", type: "search", placeholder: "Filter by address, type or stage", "aria-label": "Filter visitors" });
    const flagged = el("input", { type: "checkbox" });
    flagged.checked = true;
    const tbody = el("tbody");
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      const list = sessions.filter((s) => (!flagged.checked || s.risk_score > 0) && (!q || haystack(s).includes(q)));
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
          el("td", { class: "ipcell" }, s.ip),
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

    put(
      !saved ? el("div", { class: "notice warn banner" }, "Opened from a file. This result is not saved to your account.") : null,
      data.sample ? el("div", { class: "notice warn banner" }, "Sample data for the interface only. Do not quote these numbers.") : null,
      verdict(attacks, data.sessions_flagged ?? sessions.filter((x) => x.risk_score > 0).length, null),
      el("section", { class: "kpis summary", "aria-label": "Summary" },
        kpi("Requests read", num(data.parsed ?? timeline.length), `${num(data.skipped || 0)} lines skipped, ${data.format || "unknown format"}`),
        kpi("Visitors flagged", `${num(data.sessions_flagged ?? 0)} / ${num(data.sessions_total ?? sessions.length)}`, levelText(sessions)),
        kpi("Attack requests", num(attacks), `${num(payload)} by payload, ${num(attacks - payload)} by behaviour`, "threat"),
        kpi("Suggested blocks", num(blocked), `${num(sessions.filter((s) => s.action === "rate_limit").length)} rate limits`),
        kpi("Mode", nice(data.mode || "sensitive"), `threshold ${data.threshold ?? "–"}${data.seconds ? `, ${data.seconds} s` : ""}`)),
      el("section", { class: "panel" },
        el("div", { class: "toolbar" }, el("h2", {}, "Visitors"), el("span", { class: "grow" }), search, el("label", { class: "check" }, flagged, "Flagged only")),
        el("div", { class: "table-wrap" }, el("table", { class: "t sessions" },
          el("colgroup", {}, el("col", { class: "c-risk" }), el("col", { class: "c-ip" }), el("col"), el("col", { class: "c-req" }), el("col", { class: "c-stage" }), el("col", { class: "c-act" })),
          el("thead", {}, el("tr", {}, ["Risk", "Visitor", "What happened", "Requests", "Stage", "Action"].map((h, i) => el("th", { class: i === 3 ? "num" : null }, h)))),
          tbody)),
        el("p", { class: "note" }, "A visitor is one address and browser, with gaps under 30 minutes. Select a row for the reasons, the timeline and the fixes.")));
  }
  function haystack(s) {
    return [s.ip, s.risk_level, s.stage, s.action, ...(s.behaviours || []), ...(s.attack_types || [])]
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
      fixes(s), rules(s));
    return el("div", { class: "detail" }, el("div", { class: "detail-grid" }, left, right),
      el("h3", {}, `Timeline, ${num((s.timeline || []).length)} requests`), timelineTable(s));
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
  function timelineTable(s) {
    const t = s.timeline || [];
    const only = el("input", { type: "checkbox" });
    const tbody = el("tbody");
    const fill = () => tbody.replaceChildren(...t.filter((r) => !only.checked || r.is_attack).slice(0, 500).map((r) =>
      el("tr", { class: r.is_attack ? "attack" : "" },
        el("td", { class: "nowrap" }, fmtTime(r.timestamp).slice(11) || "–"),
        el("td", { class: "req" }, `${r.method} ${r.path}`, r.body ? el("div", { class: "muted" }, `body: ${r.body}`) : null),
        el("td", {}, r.status ?? "–"),
        el("td", { class: "num" }, r.attack_prob == null ? "–" : Number(r.attack_prob).toFixed(2)),
        el("td", {}, r.attack_type ? nice(r.attack_type) : r.is_attack ? "Attack" : "–",
          r.reasons?.length ? el("div", { class: "muted small" }, r.reasons.join("; ")) : null),
        el("td", { class: "hide-sm" }, r.unusual ? el("span", { class: "chip", title: "Rare in this log. A review mark only; it never changes detection." }, "Unusual") : ""))));
    only.addEventListener("change", fill);
    only.addEventListener("click", (e) => e.stopPropagation());
    fill();
    return el("div", {},
      el("label", { class: "check", style: "margin-bottom:8px" }, only, "Attack requests only"),
      el("div", { class: "table-wrap" }, el("table", { class: "t timeline" },
        el("thead", {}, el("tr", {}, ["Time", "Request", "Status", "Score", "Type and why", "Review"].map((h, i) => el("th", { class: i === 3 ? "num" : i === 5 ? "hide-sm" : null }, h)))),
        tbody)),
      t.length > 500 ? el("p", { class: "note" }, `Showing the first 500 of ${num(t.length)} requests. The saved JSON has all of them.`) : null,
      el("p", { class: "note" }, "Score is the detector's attack probability. A request is an attack by payload when the score reaches the mode's threshold, or by behaviour from the whole visit."));
  }
  function download(data) {
    const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: "application/json" })),
      download: `${String(data.filename || "log").replace(/\.[^.]+$/, "")}-investigation.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ---------------------------------------------------------------- account
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
    const form = el("form", { class: "form", novalidate: true },
      el("div", { class: "field" }, el("label", { for: "a-cur" }, "Current password"), cur),
      el("div", { class: "field" }, el("label", { for: "a-new" }, "New password"), nw, el("span", { class: "help" }, "At least 10 characters.")),
      el("div", { class: "field" }, el("label", { for: "a-new2" }, "Repeat the new password"), nw2),
      el("div", { class: "field" }, el("label", { for: "a-code" }, "Code from your authenticator app"), code),
      btn, msg);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      msg.hidden = true;
      if (nw.value !== nw2.value) { msg.className = "notice error"; msg.textContent = "The two new passwords are different."; msg.hidden = false; return; }
      btn.disabled = true;
      try {
        await api("/api/account/password", { method: "POST", json: { current_password: cur.value, new_password: nw.value, code: code.value } });
        msg.className = "notice ok"; msg.textContent = "Password changed. Log in again with the new password."; msg.hidden = false;
        setTimeout(() => location.replace("/login"), 1800);
      } catch (err) { msg.className = "notice error"; msg.textContent = err.message; msg.hidden = false; btn.disabled = false; }
      finally { cur.value = nw.value = nw2.value = code.value = ""; }
    });
    put(el("div", { class: "account" },
      el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Your account")),
        el("dl", { class: "facts" },
          el("dt", {}, "User name"), el("dd", {}, info.username),
          el("dt", {}, "Member since"), el("dd", {}, fmtDate(info.created_at)),
          el("dt", {}, "Last login"), el("dd", {}, fmtDate(info.last_login)),
          el("dt", {}, "Two-factor login"), el("dd", {}, "On")),
        el("p", { class: "note", style: "margin-top:18px" }, "Lost your phone? The project team can reset two-factor login on the server.")),
      el("section", { class: "panel" }, el("div", { class: "panel-head" }, el("h2", {}, "Change password")), form)));
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
    api("/health").then((h) => {
      $("#server .dot").className = `dot ${h.model_loaded ? "ok" : "bad"}`;
      $("#server span:last-child").textContent = h.model_loaded ? "Models loaded" : "Models not loaded";
    }).catch(() => { $("#server span:last-child").textContent = "Server not reachable"; });
    window.addEventListener("hashchange", route);
    route();
  }
  boot();
})();
