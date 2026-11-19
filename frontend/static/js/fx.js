"use strict";
// Shared motion for every page: scroll reveal, the pointer light on glass cards, and tilt.
// Only classes and CSS variables are set (CSSOM), so the page's strict CSP still holds.
(function () {
  const root = document.documentElement;
  root.classList.remove("no-js");
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const finePointer = window.matchMedia("(pointer: fine)").matches;

  /** Reveal elements with .reveal as they enter the screen; data-d sets a delay in seconds. */
  function reveal(scope) {
    const items = [...(scope || document).querySelectorAll(".reveal:not(.in)")];
    items.forEach((n) => { if (n.dataset.d) n.style.setProperty("--d", `${parseFloat(n.dataset.d) || 0}s`); });
    if (still || !("IntersectionObserver" in window)) { items.forEach((n) => n.classList.add("in")); return; }
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add("in");
        e.target.dispatchEvent(new CustomEvent("reveal"));
        io.unobserve(e.target);
      }
    }, { threshold: 0.14, rootMargin: "0px 0px -6% 0px" });
    items.forEach((n) => io.observe(n));
  }

  /** The light spot that follows the pointer over .glass.lit cards. */
  if (finePointer && !still) {
    document.addEventListener("pointermove", (ev) => {
      const card = ev.target instanceof Element ? ev.target.closest(".lit") : null;
      if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${ev.clientX - r.left}px`);
      card.style.setProperty("--my", `${ev.clientY - r.top}px`);
    }, { passive: true });

    document.querySelectorAll(".tilt").forEach((card) => {
      card.addEventListener("pointermove", (ev) => {
        const r = card.getBoundingClientRect();
        const x = (ev.clientX - r.left) / r.width - 0.5, y = (ev.clientY - r.top) / r.height - 0.5;
        card.style.setProperty("--ry", `${(x * 7).toFixed(2)}deg`);
        card.style.setProperty("--rx", `${(-y * 7).toFixed(2)}deg`);
      });
      card.addEventListener("pointerleave", () => { card.style.setProperty("--rx", "0deg"); card.style.setProperty("--ry", "0deg"); });
    });
  }

  /** Count a number up from 0 when it comes into view. */
  function countUp(node) {
    const target = parseFloat(node.dataset.count);
    const dec = parseInt(node.dataset.dec || "0", 10);
    const fmt = (v) => v.toLocaleString("en", { minimumFractionDigits: dec, maximumFractionDigits: dec });
    if (still) { node.textContent = fmt(target); return; }
    const t0 = performance.now(), dur = 1600;
    (function step(t) {
      const k = Math.min(1, (t - t0) / dur), ease = 1 - Math.pow(1 - k, 4);
      node.textContent = fmt(target * ease);
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  }

  window.FX = { reveal, countUp, still };
  reveal();
})();
