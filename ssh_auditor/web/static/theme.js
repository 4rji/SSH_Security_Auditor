"use strict";

// Dark/light theme switch shared by every page. Dark is the default; the choice is kept
// in this browser only. The <head> of each page applies a saved choice before painting.
const THEME_KEY = "sshAuditor.theme";

function setupThemeButton(btn) {
  const root = document.documentElement;
  const label = () => { btn.textContent = root.dataset.theme === "light" ? "Dark mode" : "Light mode"; };
  btn.addEventListener("click", () => {
    const next = root.dataset.theme === "light" ? "dark" : "light";
    if (next === "light") root.dataset.theme = "light"; else delete root.dataset.theme;
    try { localStorage.setItem(THEME_KEY, next); } catch (_) {}
    label();
  });
  label();
}
