import { $ } from "./dom.js";

let sectionLoaders = {};

export function configureNavigation(loaders) {
  sectionLoaders = loaders;
}

export function setTheme(dark) {
  document.body.classList.toggle("dark", dark);
  $("themeButton").textContent = dark ? "Light mode" : "Dark mode";
  try {
    localStorage.setItem("graylogDark", dark ? "1" : "0");
  } catch {
    // Theme persistence is optional when browser storage is unavailable.
  }
}

export function toggleTheme() {
  setTheme(!document.body.classList.contains("dark"));
}

export function toggleMenu() {
  $("navLinks").classList.toggle("open");
}

export async function showSection(id) {
  document
    .querySelectorAll(".page-section")
    .forEach((section) =>
      section.classList.toggle("active", section.id === id),
    );
  document
    .querySelectorAll(".nav-links a[data-section]")
    .forEach((link) =>
      link.classList.toggle("active", link.dataset.section === id),
    );
  $("navLinks").classList.remove("open");
  await sectionLoaders[id]?.();
}

export function sectionFromHash() {
  return (
    {
      "#clients": "clientsSection",
      "#queries": "queriesSection",
      "#audit": "auditSection",
    }[location.hash] || "graylogSection"
  );
}

export function initializeTheme() {
  let dark = matchMedia("(prefers-color-scheme: dark)").matches;
  try {
    const stored = localStorage.getItem("graylogDark");
    if (stored !== null) dark = stored === "1";
  } catch {
    // Keep the system preference.
  }
  setTheme(dark);
}
