"use strict";
// Log in (password, then 2FA code) and request access (password, then 2FA setup).
(function () {
  const views = ["v-login", "v-code", "v-signup", "v-setup", "v-done"];
  let ticket = null;          // proof from the server that the first step passed; kept only in memory

  function show(id) {
    for (const v of views) $("#" + v).hidden = v !== id;
    const signup = ["v-signup", "v-setup", "v-done"].includes(id);
    $("#tab-login").setAttribute("aria-selected", String(!signup));
    $("#tab-signup").setAttribute("aria-selected", String(signup));
    document.title = (signup ? "Request access" : "Log in") + " · AI Attack Investigator";
    const first = $("#" + id).querySelector("input");
    if (first) first.focus();
  }
  function say(form, text, kind = "error") {
    const box = form.querySelector(".notice");
    box.hidden = !text;
    box.className = `notice ${kind}`;
    box.textContent = text || "";
  }
  // The falcon beside the form reacts: a shake on a mistake, a green eye on success.
  let calm = 0;
  function mood(state) {
    const f = document.querySelector("#side-falcon .falcon");
    if (!f || !window.Falcon) return;
    Falcon.setState(f, state);
    clearTimeout(calm);
    if (state === "error") calm = setTimeout(() => Falcon.setState(f, "watch"), 1400);
  }
  async function busy(form, fn) {
    const btn = form.querySelector("button[type=submit]");
    btn.disabled = true;
    try { await fn(); } catch (e) { say(form, e.message); mood("error"); } finally { btn.disabled = false; }
  }

  // Already logged in? Go straight to the dashboard.
  api("/me").then(() => location.replace("/app")).catch(() => {});

  $("#v-login").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      say(f, "");
      const r = await api("/login", { method: "POST", json: { username: $("#l-user").value.trim(), password: $("#l-pass").value } });
      ticket = r.ticket;
      $("#l-pass").value = "";
      $("#l-code").value = "";
      say($("#v-code"), "");
      show("v-code");
    });
  });

  $("#v-code").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      try {
        await api("/login/2fa", { method: "POST", json: { ticket, code: $("#l-code").value } });
      } catch (err) {
        if (err.status === 401) { ticket = null; show("v-login"); say($("#v-login"), err.message); mood("error"); return; }
        $("#l-code").select();
        throw err;
      }
      ticket = null;
      mood("safe");
      await new Promise((ok) => setTimeout(ok, 650));
      location.replace("/app");
    });
  });

  $("#v-signup").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      if ($("#s-pass").value !== $("#s-pass2").value) throw new Error("The two passwords are different.");
      const r = await api("/signup", { method: "POST", json: { username: $("#s-user").value.trim(), password: $("#s-pass").value } });
      $("#s-pass").value = $("#s-pass2").value = "";
      ticket = r.ticket;
      const img = $("#qr-img");
      img.hidden = !r.qr;
      if (r.qr) img.src = r.qr;
      $("#qr-key").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
      show("v-setup");
    });
  });

  $("#v-setup").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      await api("/signup/2fa", { method: "POST", json: { ticket, code: $("#s-code").value } });
      ticket = null;
      $("#qr-img").removeAttribute("src");
      $("#qr-key").textContent = "";
      mood("safe");
      show("v-done");
    });
  });

  for (const b of document.querySelectorAll("[data-back]")) b.addEventListener("click", () => { ticket = null; show(b.dataset.back); });
  for (const a of document.querySelectorAll(".tabs a")) {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      history.replaceState(null, "", a.getAttribute("href"));
      ticket = null;
      show(a.id === "tab-signup" ? "v-signup" : "v-login");
    });
  }
  show(location.pathname.startsWith("/signup") ? "v-signup" : "v-login");
})();
