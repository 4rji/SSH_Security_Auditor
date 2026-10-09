"use strict";

// Page chrome shared by every page: marks the section in view in the sidebar and, on
// the auditor page, mirrors the target in the header and runs the scan from there.
(function () {
  const links = Array.from(document.querySelectorAll('.nav a[href^="#"]'));
  const sections = links.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
  const mark = (id) => links.forEach((a) => {
    if (a.getAttribute("href") === "#" + id) a.setAttribute("aria-current", "true");
    else a.removeAttribute("aria-current");
  });
  if (sections.length && "IntersectionObserver" in window) {
    const seen = new Map();
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => seen.set(e.target.id, e.isIntersecting));
      const first = sections.find((s) => seen.get(s.id));
      if (first) mark(first.id);
    }, { rootMargin: "-20% 0px -55% 0px" });
    sections.forEach((s) => obs.observe(s));
    mark(sections[0].id);
  }

  const host = document.getElementById("host");
  const port = document.getElementById("port");
  const chip = document.getElementById("targetChip");
  if (host && port && chip) {
    const text = chip.querySelector("span:last-child");
    const show = () => {
      const h = host.value.trim();
      chip.classList.toggle("live", Boolean(h));
      text.innerHTML = "";
      if (!h) { text.textContent = "No target yet"; return; }
      const b = document.createElement("b");
      b.textContent = h;
      text.append(b, `:${port.value || 22}`);
    };
    host.addEventListener("input", show);
    port.addEventListener("input", show);
    show();
  }

  const runTop = document.getElementById("runTop");
  const run = document.getElementById("run");
  if (runTop && run) {
    runTop.addEventListener("click", () => {
      const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      document.getElementById("step-run").scrollIntoView({ behavior: still ? "auto" : "smooth" });
      run.click();
    });
    // Mirror the real button while a scan runs.
    new MutationObserver(() => { runTop.disabled = run.disabled; })
      .observe(run, { attributes: true, attributeFilter: ["disabled"] });
  }
})();
