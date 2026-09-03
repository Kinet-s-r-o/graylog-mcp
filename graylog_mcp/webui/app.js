import { api } from "./api.js";
import { $ } from "./dom.js";
import { applyFilter, clearFilter, toggleFilter } from "./filters.js";
import {
  cancelDelete,
  cancelDiscard,
  cancelLogout,
  close,
  configureModalRefresh,
  confirmDelete,
  confirmDiscard,
  confirmLogout,
  openAgent,
  openDelete,
  openLogout,
  openRule,
  markFieldError,
  ruleTypeChanged,
  openServer,
  requestClose,
  submit,
  testServer,
} from "./modals.js";
import {
  configureNavigation,
  initializeTheme,
  sectionFromHash,
  showSection,
  toggleMenu,
  toggleTheme,
} from "./navigation.js";
import { notify } from "./notifications.js";
import {
  renderAgents,
  renderAudit,
  renderQueries,
  renderServers,
  renderers,
  sortQueries,
} from "./tables.js";
import { state } from "./state.js";

let auditSearchTimer = null;

async function loadServers() {
  try {
    state.servers = (await api.servers()).items || [];
    renderServers();
  } catch (error) {
    notify(error.message, "error");
  }
}

async function loadAgents() {
  try {
    if (!state.servers.length) await loadServers();
    state.agents = (await api.agents()).items || [];
    renderAgents();
  } catch (error) {
    notify(error.message, "error");
  }
}

async function loadQueries() {
  try {
    state.queries = (await api.queries()).queries || [];
    renderQueries();
  } catch (error) {
    notify(error.message, "error");
  }
}

async function loadAudit(page = 1) {
  const params = new URLSearchParams({
    page: String(page),
    limit: $("auditPageSize").value,
  });
  if ($("auditSearch").value) params.set("q", $("auditSearch").value);
  if ($("auditSource").value) params.set("source", $("auditSource").value);
  try {
    renderAudit(await api.audit(params));
  } catch (error) {
    $("auditOut").innerHTML = `<p class="audit-empty failed"></p>`;
    $("auditOut").querySelector("p").textContent = error.message;
  }
}

function scheduleAuditSearch() {
  clearTimeout(auditSearchTimer);
  auditSearchTimer = setTimeout(() => loadAudit(1), 250);
}

function configureAuditRefresh() {
  if (state.auditRefreshTimer) {
    clearInterval(state.auditRefreshTimer);
    state.auditRefreshTimer = null;
  }
  const seconds = Number($("auditRefresh").value);
  if (!seconds) return;
  state.auditRefreshTimer = setInterval(() => {
    if ($("auditSection").classList.contains("active")) {
      loadAudit(state.auditPage);
    }
  }, seconds * 1000);
}

configureModalRefresh({
  servers: loadServers,
  agents: loadAgents,
  queries: loadQueries,
});
configureNavigation({
  graylogSection: loadServers,
  clientsSection: loadAgents,
  queriesSection: loadQueries,
  auditSection: () => loadAudit(state.auditPage),
});

function item(kind, target) {
  if (kind === "server")
    return state.servers.find((entry) => entry.id === Number(target));
  if (kind === "agent")
    return state.agents.find((entry) => entry.id === Number(target));
  return state.queries.find((entry) => entry.name === target);
}

const actions = {
  "toggle-menu": () => toggleMenu(),
  "toggle-theme": () => toggleTheme(),
  "open-logout": () => openLogout(),
  "add-server": () => openServer(),
  "add-agent": () => openAgent(),
  "add-rule": () => openRule(),
  "close-modal": () => requestClose(),
  "cancel-discard": () => cancelDiscard(),
  "confirm-discard": () => confirmDiscard(),
  "cancel-delete": () => cancelDelete(),
  "confirm-delete": () => confirmDelete(),
  "cancel-logout": () => cancelLogout(),
  "confirm-logout": () => confirmLogout(),
  "test-server": () => testServer(),
  "audit-page-size": () => loadAudit(1),
  "audit-refresh": () => {
    configureAuditRefresh();
    return loadAudit(state.auditPage);
  },
  "audit-page": (button) =>
    loadAudit(state.auditPage + Number(button.dataset.delta)),
  "edit-server": (button) => openServer(item("server", button.dataset.id)),
  "edit-agent": (button) => openAgent(item("agent", button.dataset.id)),
  "edit-rule": (button) => openRule(item("rule", button.dataset.name)),
  "delete-server": (button) => {
    const selected = item("server", button.dataset.id);
    if (selected) openDelete("server", selected.id, selected.name);
  },
  "delete-agent": (button) => {
    const selected = item("agent", button.dataset.id);
    if (selected) openDelete("agent", selected.id, selected.name);
  },
  "delete-rule": (button) => {
    const selected = item("rule", button.dataset.name);
    if (selected) openDelete("rule", selected.name, selected.name);
  },
  "toggle-filter": (button) =>
    toggleFilter(button.dataset.table, button.dataset.key),
  "apply-filter": (button) => {
    applyFilter(button.dataset.table, button.dataset.key);
    renderers[button.dataset.table]();
  },
  "clear-filter": (button) => {
    clearFilter(button.dataset.table, button.dataset.key);
    renderers[button.dataset.table]();
  },
  sort: (button) => sortQueries(button.dataset.key),
  "select-api-key": (input) => input.select(),
};

document.addEventListener("click", async (event) => {
  const navLink = event.target.closest(".nav-links a[data-section]");
  if (navLink) {
    event.preventDefault();
    history.replaceState(null, "", navLink.getAttribute("href"));
    await showSection(navLink.dataset.section);
    return;
  }
  const control = event.target.closest("[data-action]");
  if (!control || control.matches("select")) return;
  event.preventDefault();
  await actions[control.dataset.action]?.(control);
});

document.addEventListener("dblclick", (event) => {
  if (event.target.closest("button,a,input,select,textarea")) return;
  const row = event.target.closest("[data-edit-kind]");
  if (!row) return;
  const target = row.dataset.id || row.dataset.name;
  const selected = item(row.dataset.editKind, target);
  if (row.dataset.editKind === "server") openServer(selected);
  else if (row.dataset.editKind === "agent") openAgent(selected);
  else openRule(selected);
});

document.addEventListener("keydown", (event) => {
  const filterInput = event.target.closest("[data-filter-input]");
  if (filterInput && event.key === "Enter") {
    event.preventDefault();
    applyFilter(filterInput.dataset.table, filterInput.dataset.key);
    renderers[filterInput.dataset.table]();
  } else if (event.key === "Escape" && !$("editModal").hidden) {
    requestClose();
  }
});

document.addEventListener("input", (event) => {
  if (event.target.id === "auditSearch") scheduleAuditSearch();
});

document.addEventListener(
  "invalid",
  (event) => {
    if (event.target.closest("#editForm")) {
      markFieldError(event.target.id, event.target.validationMessage);
    }
  },
  true,
);

document.addEventListener("change", (event) => {
  if (event.target.id === "auditSource") scheduleAuditSearch();
  if (event.target.id === "mRuleType") ruleTypeChanged();
  const control = event.target.closest('[data-action^="audit-"]');
  if (control) actions[control.dataset.action]?.(control);
});

$("editForm").addEventListener("submit", submit);
window.addEventListener("hashchange", () => showSection(sectionFromHash()));

initializeTheme();
showSection(sectionFromHash());
configureAuditRefresh();
