export const $ = (id) => document.getElementById(id);

export function escapeHtml(value) {
  return String(value ?? "—")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function setDocumentBusy(busy) {
  document.body.classList.toggle("loading", busy);
  document.body.setAttribute("aria-busy", String(busy));
}
