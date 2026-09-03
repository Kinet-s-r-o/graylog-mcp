import { api } from "./api.js";
import { $, escapeHtml } from "./dom.js";
import { notify } from "./notifications.js";
import { state } from "./state.js";

let refresh = {
  servers: async () => {},
  agents: async () => {},
  queries: async () => {},
};

export function configureModalRefresh(callbacks) {
  refresh = callbacks;
}

function field(label, id, value = "", type = "text", placeholder = "") {
  return `<div><label for="${id}">${label}</label><input id="${id}" type="${type}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}"></div>`;
}

function textarea(label, id, value = "") {
  return `<label for="${id}">${label}</label><textarea id="${id}">${escapeHtml(value)}</textarea>`;
}

function values() {
  return [
    ...document.querySelectorAll(
      "#modalFields input,#modalFields select,#modalFields textarea",
    ),
  ].map((item) => item.value);
}

function open(kind, title, fields, item = null) {
  state.modal = { kind, item, initialValues: [] };
  $("modalTitle").textContent = title;
  $("modalFields").innerHTML = fields;
  $("modalStatus").textContent = "";
  $("testModalButton").hidden = kind !== "server";
  $("editModal").hidden = false;
  state.modal.initialValues = values();
  document.body.style.overflow = "hidden";
  setTimeout(
    () =>
      document
        .querySelector("#editModal input,#editModal textarea,#editModal select")
        ?.focus(),
    0,
  );
}

function options(items, selected) {
  return items
    .map(
      (item) =>
        `<option value="${item.id}" ${String(item.id) === String(selected) ? "selected" : ""}>${escapeHtml(item.name)}${item.url ? ` — ${escapeHtml(item.url)}` : ""}</option>`,
    )
    .join("");
}

export function openServer(item = null) {
  const server = item || {};
  const tls =
    server.verify_tls === undefined ? true : Boolean(server.verify_tls);
  open(
    "server",
    item ? "Edit Graylog server" : "Add Graylog server",
    `<div class="grid">${field("Name", "mServerName", server.name, "text", "production")}${field("URL", "mServerUrl", server.url, "url", "https://graylog.example.com")}${field("API token", "mServerToken", "", "password", item ? "Leave blank to keep the current token" : "Graylog API token")}${field("Timeout (seconds)", "mServerTimeout", server.timeout_seconds || 30, "number")}<div><label for="mServerTls">Verify TLS</label><select id="mServerTls"><option value="true" ${tls ? "selected" : ""}>Yes</option><option value="false" ${!tls ? "selected" : ""}>No</option></select></div></div>`,
    item,
  );
}

export function openAgent(item = null) {
  const agent = item || {};
  open(
    "agent",
    item ? "Edit MCP client" : "Add MCP client",
    `<div class="grid">${field("Client name", "mAgentName", agent.name, "text", "monitoring-agent")}<div><label for="mAgentServer">Assigned Graylog server</label><select id="mAgentServer">${options(state.servers, agent.graylog_server_id)}</select></div>${field("API key", "mAgentKey", "", "password", item ? "Leave blank to keep the current key" : "Leave blank to generate")}${item ? `<div><label for="mAgentActive">Status</label><select id="mAgentActive"><option value="true" ${agent.active ? "selected" : ""}>Active</option><option value="false" ${!agent.active ? "selected" : ""}>Inactive</option></select></div>` : ""}</div>${textarea("Allowed source IPs (CIDR)", "mAgentAllowedIps", (agent.allowed_ips || []).join("\n"))}`,
    item,
  );
}

export function openRule(item = null) {
  const query = item || {};
  open(
    "rule",
    item ? "Edit query rule" : "Add query rule",
    `${field("Name", "mRuleName", query.name, "text", "errors_by_service")}${field("Description", "mRuleDescription", query.description || "", "text", "Count errors grouped by service")}<div class="grid"><div><label for="mRuleType">Type</label><select id="mRuleType"><option value="messages" ${query.type !== "aggregate" ? "selected" : ""}>Message search</option><option value="aggregate" ${query.type === "aggregate" ? "selected" : ""}>Aggregation</option></select></div>${field("Time range (minutes)", "mRuleMinutes", query.minutes || 60, "number")}${field("Message limit", "mRuleLimit", query.limit || 100, "number")}${field("Time bucket", "mRuleInterval", query.interval || "", "text", "5m")}</div>${textarea("Lucene query template", "mRuleQuery", query.query || "")}${textarea("Group by JSON", "mRuleGroup", JSON.stringify(query.group_by || [], null, 2))}${textarea("Metrics JSON", "mRuleMetrics", JSON.stringify(query.metrics || [{ function: "count" }], null, 2))}${textarea("Default parameters JSON", "mRuleDefaults", JSON.stringify(query.defaults || {}, null, 2))}${textarea("Instructions for the agent", "mRuleInstructions", query.instructions || "")}`,
    item,
  );
}

export function requestClose() {
  const dirty = values().some(
    (value, index) => value !== state.modal.initialValues[index],
  );
  if (dirty) $("discardModal").hidden = false;
  else close();
}

export function close() {
  $("editModal").hidden = true;
  $("discardModal").hidden = true;
  document.body.style.overflow = "";
  state.modal = { kind: "", item: null, initialValues: [] };
}

export function cancelDiscard() {
  $("discardModal").hidden = true;
}

export function confirmDiscard() {
  close();
}

export function openDelete(kind, id, name) {
  state.deletion = { kind, id };
  $("deleteTitle").textContent =
    `Delete ${kind === "server" ? "Graylog server" : kind === "agent" ? "MCP client" : "query rule"}?`;
  $("deleteMessage").textContent =
    `Are you sure you want to delete “${name}”? This action cannot be undone.`;
  $("deleteModal").hidden = false;
}

export function cancelDelete() {
  $("deleteModal").hidden = true;
  state.deletion = { kind: "", id: null };
}

export async function confirmDelete() {
  const { kind, id } = state.deletion;
  cancelDelete();
  try {
    if (kind === "server") {
      await api.deleteServer(id);
      await refresh.servers();
    } else if (kind === "agent") {
      await api.deleteAgent(id);
      await refresh.agents();
    } else {
      await api.deleteQuery(id);
      await refresh.queries();
    }
    notify("Record deleted.", "success");
  } catch (error) {
    notify(error.message, "error");
  }
}

function serverPayload() {
  return {
    name: $("mServerName").value.trim(),
    url: $("mServerUrl").value.trim(),
    api_token: $("mServerToken").value,
    verify_tls: $("mServerTls").value === "true",
    timeout_seconds: Number($("mServerTimeout").value) || 30,
  };
}

export async function testServer() {
  const payload = serverPayload();
  if (state.modal.item) payload.server_id = state.modal.item.id;
  $("modalStatus").textContent = "Testing connection…";
  try {
    const result = await api.testServer(payload);
    $("modalStatus").textContent = `✓ ${result.message}`;
    $("modalStatus").className = "status-message success";
  } catch (error) {
    $("modalStatus").textContent = `✗ ${error.message}`;
    $("modalStatus").className = "status-message failed";
  }
}

export async function submit(event) {
  event.preventDefault();
  const { kind, item } = state.modal;
  try {
    let result;
    if (kind === "server") {
      const payload = serverPayload();
      if (item) payload.server_id = item.id;
      result = await api.saveServer(payload, Boolean(item));
      await refresh.servers();
    } else if (kind === "agent") {
      const payload = {
        name: $("mAgentName").value.trim(),
        graylog_server_id: Number($("mAgentServer").value),
        allowed_ips: $("mAgentAllowedIps").value,
      };
      if ($("mAgentKey").value) payload.api_key = $("mAgentKey").value;
      if (item) {
        payload.agent_id = item.id;
        payload.active = $("mAgentActive").value === "true";
      }
      result = await api.saveAgent(payload, Boolean(item));
      await refresh.agents();
    } else {
      result = await api.saveQuery({
        name: $("mRuleName").value.trim(),
        description: $("mRuleDescription").value,
        type: $("mRuleType").value,
        query: $("mRuleQuery").value,
        minutes: Number($("mRuleMinutes").value),
        limit: Number($("mRuleLimit").value),
        interval: $("mRuleInterval").value,
        group_by: JSON.parse($("mRuleGroup").value),
        metrics: JSON.parse($("mRuleMetrics").value),
        defaults: JSON.parse($("mRuleDefaults").value),
        instructions: $("mRuleInstructions").value,
      });
      await refresh.queries();
    }
    if (kind === "agent" && !item && result.api_key) {
      $("modalStatus").innerHTML =
        `<span class="success">✓ Client created. Copy this API key now; it will not be shown again.</span><label for="generatedApiKey">Generated API key</label><input id="generatedApiKey" value="${escapeHtml(result.api_key)}" readonly data-action="select-api-key">`;
      state.modal.initialValues = values();
      return;
    }
    close();
    notify("Changes saved.", "success");
  } catch (error) {
    $("modalStatus").textContent = `✗ ${error.message}`;
    $("modalStatus").className = "status-message failed";
  }
}

export function openLogout() {
  $("logoutMessage").textContent =
    "Are you sure you want to sign out of the WebUI?";
  $("logoutModal").hidden = false;
  document.body.style.overflow = "hidden";
}

export function cancelLogout() {
  $("logoutModal").hidden = true;
  document.body.style.overflow = "";
}

export async function confirmLogout() {
  try {
    await api.logout();
    location.assign("/login");
  } catch (error) {
    $("logoutMessage").textContent = error.message;
  }
}
