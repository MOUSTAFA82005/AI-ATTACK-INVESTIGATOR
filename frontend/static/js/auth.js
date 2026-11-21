"use strict";
// Log in (password, then an e-mailed code) and create an account (password, then confirm the e-mail).
(function () {
  const views = ["v-login", "v-code", "v-signup", "v-setup", "v-done"];
  let ticket = null;          // proof from the server that the first step passed; kept only in memory

  // Grow or shrink the card smoothly instead of jumping to the new height.
  let resizeRun = 0;
  function resizeCard(change) {
    const run = ++resizeRun;
    const card = $(".auth-card");
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!card || reduce) { change(); return; }
    const from = card.offsetHeight;
    card.classList.remove("resizing");
    card.style.height = "";
    change();
    const to = card.offsetHeight;
    if (Math.abs(to - from) < 2) return;
    card.style.height = from + "px";
    void card.offsetHeight;
    card.classList.add("resizing");
    card.style.height = to + "px";
    const done = (ev) => {
      if ((ev && ev.target !== card) || run !== resizeRun) return;
      card.removeEventListener("transitionend", done);
      card.classList.remove("resizing");
      card.style.height = "";
    };
    card.addEventListener("transitionend", done);
    setTimeout(done, 500);
  }
  function show(id) {
    resizeCard(() => { for (const v of views) $("#" + v).hidden = v !== id; });
    const signup = ["v-signup", "v-setup", "v-done"].includes(id);
    $("#tab-login").setAttribute("aria-selected", String(!signup));
    $("#tab-signup").setAttribute("aria-selected", String(signup));
    document.title = (signup ? "Create account" : "Log in") + " · TALON INVESTIGATOR";
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
    try { await fn(); } catch (e) {
      say(form, e.message); mood("error");
      const code = form.querySelector(".otp-source");
      if (code && code.otpReset) { code.otpReset(); code.otpShake(); code.otpFocus(); }
    } finally { btn.disabled = false; }
  }

  otp($("#l-code"));
  otp($("#s-code"));

  // Already logged in? Go straight to the dashboard.
  api("/me").then(() => location.replace("/app")).catch(() => {});

  const sentTo = (view, who) => { for (const b of $("#" + view).querySelectorAll(".sent-to")) b.textContent = who; };

  $("#v-login").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      say(f, "");
      const r = await api("/login", { method: "POST", json: { login: $("#l-user").value.trim(), password: $("#l-pass").value } });
      ticket = r.ticket;
      $("#l-pass").value = "";
      $("#l-code").otpReset();
      say($("#v-code"), "");
      sentTo("v-code", r.sent_to);
      show("v-code");
    });
  });

  $("#v-code").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      try {
        await api("/login/code", { method: "POST", json: { ticket, code: $("#l-code").value } });
      } catch (err) {
        if (err.status === 401) { ticket = null; show("v-login"); say($("#v-login"), err.message); mood("error"); return; }
        throw err;
      }
      ticket = null;
      mood("safe");
      await new Promise((ok) => setTimeout(ok, 650));
      location.replace("/app");
    });
  });

  // Live password checklist on sign-up (the server checks the same rules).
  const signupRules = passwordMeter($("#s-pass"), () => [$("#s-name").value.trim(), $("#s-user").value.trim()]);
  $("#s-rules").replaceWith(signupRules);
  for (const id of ["#s-name", "#s-user"]) $(id).addEventListener("input", () => signupRules.redraw());

  $("#v-signup").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      const weak = passwordRules($("#s-pass").value, $("#s-name").value.trim(), $("#s-user").value.trim()).find(([, ok]) => !ok);
      if (weak) throw new Error(`The password needs: ${weak[0].toLowerCase()}.`);
      if ($("#s-pass").value !== $("#s-pass2").value) throw new Error("The two passwords are different.");
      const r = await api("/signup", { method: "POST", json: { username: $("#s-name").value.trim(), email: $("#s-user").value.trim(), password: $("#s-pass").value } });
      $("#s-pass").value = $("#s-pass2").value = "";
      ticket = r.ticket;
      $("#s-code").otpReset();
      say($("#v-setup"), "");
      sentTo("v-setup", r.sent_to);
      show("v-setup");
    });
  });

  $("#v-setup").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.currentTarget;
    busy(f, async () => {
      let done;
      try {
        done = await api("/signup/verify", { method: "POST", json: { ticket, code: $("#s-code").value } });
      } catch (err) {
        if (err.status === 401) { ticket = null; show("v-signup"); say($("#v-signup"), err.message); mood("error"); return; }
        throw err;
      }
      ticket = null;
      const ready = done.status === "active";
      $("#done-title").textContent = ready ? "Account ready" : "Request sent";
      $("#done-text").textContent = done.message;
      $("#done-go").textContent = ready ? "Log in now" : "Back to log in";
      mood("safe");
      show("v-done");
    });
  });

  // "Send a new code": the same ticket gets a fresh code (the server allows one every 30 s).
  for (const b of document.querySelectorAll("[data-resend]")) {
    b.addEventListener("click", async () => {
      const form = b.closest("form");
      b.disabled = true;
      try {
        const r = await api("/code/resend", { method: "POST", json: { ticket, purpose: b.dataset.resend } });
        say(form, `A new code is on its way to ${r.sent_to}.`, "ok");
        form.querySelector(".otp-source").otpReset();
        form.querySelector(".otp-source").otpFocus();
      } catch (err) {
        say(form, err.message);
      } finally {
        setTimeout(() => { b.disabled = false; }, 30000);
      }
    });
  }

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
