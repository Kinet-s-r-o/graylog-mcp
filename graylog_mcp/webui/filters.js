import { $, escapeHtml } from "./dom.js";
import { state } from "./state.js";

export function matchesFilters(item, table) {
  return Object.entries(state.filters[table]).every(([key, filter]) => {
    const actual = String(item[key] ?? "").toLocaleLowerCase();
    return filter.mode === "equals"
      ? actual === filter.value
      : actual.includes(filter.value);
  });
}

export function filterHeader(label, table, key, sortable = false) {
  const active = state.filters[table][key];
  const title = sortable
    ? `<button class="sort-header" data-action="sort" data-key="${key}">${label}<span class="sort-icon" aria-hidden="true">${sortIcon(key)}</span></button>`
    : `<span>${label}</span>`;
  return `<th><div class="filter-header">${title}<button class="filter-button ${active ? "active" : ""}" data-action="toggle-filter" data-table="${table}" data-key="${key}" aria-label="Filter ${label}">▽</button><div id="filter-${table}-${key}" class="filter-popover" hidden><label for="filter-mode-${table}-${key}">Condition</label><select id="filter-mode-${table}-${key}"><option value="contains" ${active?.mode === "contains" || !active ? "selected" : ""}>Contains</option><option value="equals" ${active?.mode === "equals" ? "selected" : ""}>Equals</option></select><label for="filter-value-${table}-${key}">Value</label><input id="filter-value-${table}-${key}" value="${active ? escapeHtml(active.value) : ""}" data-filter-input="true" data-table="${table}" data-key="${key}"><div class="filter-actions"><button type="button" class="secondary" data-action="clear-filter" data-table="${table}" data-key="${key}">Clear</button><button type="button" data-action="apply-filter" data-table="${table}" data-key="${key}">Apply</button></div></div></div></th>`;
}

function sortIcon(key) {
  return state.querySort.key === key
    ? state.querySort.direction === 1
      ? "↑"
      : "↓"
    : "↕";
}

export function toggleFilter(table, key) {
  const popover = $(`filter-${table}-${key}`);
  if (!popover) return;
  if (!popover.hidden) {
    popover.hidden = true;
    return;
  }
  document
    .querySelectorAll(".filter-popover")
    .forEach((item) => (item.hidden = true));
  popover.hidden = false;
  const button = popover.parentElement.querySelector(".filter-button");
  const rect = button.getBoundingClientRect();
  popover.style.top = `${rect.bottom + 6}px`;
  popover.style.left = `${Math.min(rect.left, Math.max(8, window.innerWidth - popover.offsetWidth - 8))}px`;
  $(`filter-value-${table}-${key}`)?.focus();
}

export function applyFilter(table, key) {
  const value = $(`filter-value-${table}-${key}`).value.trim();
  const mode = $(`filter-mode-${table}-${key}`).value;
  if (value)
    state.filters[table][key] = { value: value.toLocaleLowerCase(), mode };
  else delete state.filters[table][key];
}

export function clearFilter(table, key) {
  delete state.filters[table][key];
}
