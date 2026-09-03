import { $, escapeHtml } from "./dom.js";
import { filterHeader, matchesFilters } from "./filters.js";
import { state } from "./state.js";

const empty = (message) => `<p class="audit-empty muted">${message}</p>`;

export function renderServers() {
  if (!state.servers.length) {
    $("serversOut").innerHTML = empty("No Graylog servers configured.");
    return;
  }
  const rows = state.servers.filter((item) => matchesFilters(item, "servers"));
  $("serversOut").innerHTML =
    `<table class="audit-table"><thead><tr>${filterHeader("Name", "servers", "name")}${filterHeader("URL", "servers", "url")}${filterHeader("TLS", "servers", "verify_tls")}${filterHeader("Timeout", "servers", "timeout_seconds")}<th>Created</th><th>Actions</th></tr></thead><tbody>${rows
      .map(
        (server) =>
          `<tr class="table-row" data-edit-kind="server" data-id="${server.id}"><td><strong>${escapeHtml(server.name)}</strong></td><td>${escapeHtml(server.url)}</td><td>${server.verify_tls ? "Enabled" : "Disabled"}</td><td>${escapeHtml(server.timeout_seconds)} s</td><td>${escapeHtml(server.created_at)}</td><td class="row-actions"><button class="secondary icon-button" title="Edit server" aria-label="Edit server" data-action="edit-server" data-id="${server.id}">✎</button><button class="delete-button icon-button" title="Delete server" aria-label="Delete server" data-action="delete-server" data-id="${server.id}">✕</button></td></tr>`,
      )
      .join("")}</tbody></table>`;
}

export function renderAgents() {
  if (!state.agents.length) {
    $("agentsOut").innerHTML = empty("No MCP clients configured.");
    return;
  }
  const filterable = state.agents.map((agent) => ({
    ...agent,
    status: agent.active ? "Active" : "Inactive",
  }));
  const rows = filterable.filter((item) => matchesFilters(item, "agents"));
  $("agentsOut").innerHTML =
    `<table class="audit-table"><thead><tr>${filterHeader("Name", "agents", "name")}${filterHeader("Graylog server", "agents", "graylog_server_name")}${filterHeader("API key", "agents", "api_key_last4")}${filterHeader("Status", "agents", "status")}<th>Created</th><th>Actions</th></tr></thead><tbody>${rows
      .map(
        (agent) =>
          `<tr class="table-row" data-edit-kind="agent" data-id="${agent.id}"><td><strong>${escapeHtml(agent.name)}</strong></td><td>${escapeHtml(agent.graylog_server_name)}</td><td>••••${escapeHtml(agent.api_key_last4)}</td><td><span class="badge ${agent.active ? "active" : "inactive"}">${agent.status}</span></td><td>${escapeHtml(agent.created_at)}</td><td class="row-actions"><button class="secondary icon-button" title="Edit MCP client" aria-label="Edit MCP client" data-action="edit-agent" data-id="${agent.id}">✎</button><button class="delete-button icon-button" title="Delete MCP client" aria-label="Delete MCP client" data-action="delete-agent" data-id="${agent.id}">✕</button></td></tr>`,
      )
      .join("")}</tbody></table>`;
}

export function sortQueries(key) {
  state.querySort.direction =
    state.querySort.key === key ? -state.querySort.direction : 1;
  state.querySort.key = key;
  renderQueries();
}

export function renderQueries() {
  if (!state.queries.length) {
    $("queriesOut").innerHTML = empty("No query rules configured.");
    return;
  }
  const rows = state.queries
    .filter((item) => matchesFilters(item, "queries"))
    .sort((a, b) => {
      let left = a[state.querySort.key];
      let right = b[state.querySort.key];
      if (["minutes", "limit"].includes(state.querySort.key)) {
        left = Number(left || 0);
        right = Number(right || 0);
      } else {
        left = String(left || "").toLocaleLowerCase();
        right = String(right || "").toLocaleLowerCase();
      }
      return left < right
        ? -state.querySort.direction
        : left > right
          ? state.querySort.direction
          : 0;
    });
  $("queriesOut").innerHTML =
    `<table class="audit-table"><thead><tr>${filterHeader("Name", "queries", "name", true)}${filterHeader("Description", "queries", "description", true)}${filterHeader("Type", "queries", "type", true)}${filterHeader("Time range", "queries", "minutes", true)}${filterHeader("Limit", "queries", "limit", true)}<th>Actions</th></tr></thead><tbody>${rows
      .map(
        (query) =>
          `<tr class="table-row" data-edit-kind="rule" data-name="${escapeHtml(query.name)}"><td><strong>${escapeHtml(query.name)}</strong></td><td>${escapeHtml(query.description || "—")}</td><td>${query.type === "aggregate" ? "Aggregation" : "Messages"}</td><td>${escapeHtml(query.minutes || 60)} min</td><td>${query.type === "aggregate" ? "—" : escapeHtml(query.limit || 100)}</td><td class="row-actions"><button class="secondary icon-button" title="Edit query rule" aria-label="Edit query rule" data-action="edit-rule" data-name="${escapeHtml(query.name)}">✎</button><button class="copy-button icon-button" title="Duplicate query rule" aria-label="Duplicate query rule" data-action="duplicate-rule" data-name="${escapeHtml(query.name)}">⧉</button><button class="delete-button icon-button" title="Delete query rule" aria-label="Delete query rule" data-action="delete-rule" data-name="${escapeHtml(query.name)}">✕</button></td></tr>`,
      )
      .join("")}</tbody></table>`;
}

function auditJson(value) {
  if (value === null || value === undefined || value === "") return "—";
  try {
    return escapeHtml(JSON.stringify(JSON.parse(value), null, 2));
  } catch {
    return escapeHtml(value);
  }
}

function auditQueryRule(item) {
  if (!item.request_json) return "—";
  try {
    return JSON.parse(item.request_json).query_rule || "—";
  } catch {
    return "—";
  }
}

export function renderAudit(data) {
  state.auditData = data;
  state.auditPage = data.page || 1;
  const pages = data.pages || 1;
  $("auditPageInfo").textContent = `Page ${state.auditPage} of ${pages}`;
  $("auditPrev").disabled = state.auditPage <= 1;
  $("auditNext").disabled = state.auditPage >= pages;
  const rows = (data.items || [])
    .map((item) => ({ ...item, result: item.success ? "Success" : "Failed" }))
    .filter((item) => matchesFilters(item, "audit"));
  if (!rows.length) {
    $("auditOut").innerHTML = empty("No audit records found.");
    return;
  }
  $("auditOut").innerHTML =
    `<table class="audit-table"><thead><tr><th>ID</th><th>Created</th>${filterHeader("Source", "audit", "source")}${filterHeader("MCP client", "audit", "agent_name")}${filterHeader("Client IP", "audit", "client_ip")}<th>Query rule</th>${filterHeader("Operation", "audit", "operation")}<th>Duration</th>${filterHeader("Result", "audit", "result")}<th>Details</th></tr></thead><tbody>${rows
      .map(
        (item) =>
          `<tr><td>${escapeHtml(item.id)}</td><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(item.agent_name || "—")}</td><td>${escapeHtml(item.client_ip || "—")}</td><td>${escapeHtml(auditQueryRule(item))}</td><td>${escapeHtml(item.operation)}</td><td>${item.duration_ms === null || item.duration_ms === undefined ? "—" : escapeHtml(`${Number(item.duration_ms).toFixed(1)} ms`)}</td><td class="${item.success ? "success" : "failed"}">${item.result}${item.status_code ? `<br><small>${escapeHtml(item.status_code)}</small>` : ""}</td><td><details class="audit-detail"><summary>Request / response${item.error ? " / error" : ""}</summary>${item.request_json ? `<strong>Request</strong><pre>${auditJson(item.request_json)}</pre>` : ""}${item.response_json ? `<strong>Response</strong><pre>${auditJson(item.response_json)}</pre>` : ""}${item.error ? `<strong>Error</strong><pre>${escapeHtml(item.error)}</pre>` : ""}</details></td></tr>`,
      )
      .join("")}</tbody></table>`;
}

export const renderers = {
  servers: renderServers,
  agents: renderAgents,
  queries: renderQueries,
  audit: () => renderAudit(state.auditData || { items: [], page: 1, pages: 1 }),
};
