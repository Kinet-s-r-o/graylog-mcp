import { setDocumentBusy } from "./dom.js";

const csrfToken =
  document.querySelector('meta[name="csrf-token"]')?.content || "";
let activeRequests = 0;

export class ApiError extends Error {
  constructor(message, status, code = "request_error") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function decode(response) {
  const type = response.headers.get("content-type") || "";
  if (!type.includes("application/json")) {
    return {
      detail: response.ok ? "" : "The server returned an invalid response.",
    };
  }
  return response.json();
}

export async function request(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const init = {
    ...options,
    method,
    headers,
    credentials: "same-origin",
    body:
      options.json === undefined ? options.body : JSON.stringify(options.json),
  };
  delete init.json;
  activeRequests += 1;
  setDocumentBusy(true);
  try {
    let response;
    try {
      response = await fetch(path, init);
    } catch (error) {
      if (method !== "GET") throw error;
      response = await fetch(path, init);
    }
    if (response.status === 401 && path.startsWith("/ui/api/")) {
      location.assign("/login");
      throw new ApiError("Your session has expired.", 401, "unauthorized");
    }
    const data = await decode(response);
    if (!response.ok) {
      throw new ApiError(
        data.detail || data.message || "Request failed.",
        response.status,
        data.code,
      );
    }
    return data;
  } finally {
    activeRequests -= 1;
    setDocumentBusy(activeRequests > 0);
  }
}

export const api = {
  servers: () => request("/ui/api/servers"),
  agents: () => request("/ui/api/agents"),
  queries: () => request("/ui/api/queries"),
  audit: (params) => request(`/ui/api/audit?${params}`),
  saveServer: (payload, editing) =>
    request("/ui/api/servers", {
      method: editing ? "PUT" : "POST",
      json: payload,
    }),
  testServer: (payload) =>
    request("/ui/api/servers/test", { method: "POST", json: payload }),
  saveAgent: (payload, editing) =>
    request("/ui/api/agents", {
      method: editing ? "PUT" : "POST",
      json: payload,
    }),
  saveQuery: (payload) =>
    request("/ui/api/queries", { method: "POST", json: payload }),
  deleteServer: (id) =>
    request(`/ui/api/servers?id=${id}`, { method: "DELETE" }),
  deleteAgent: (id) => request(`/ui/api/agents?id=${id}`, { method: "DELETE" }),
  deleteQuery: (name) =>
    request(`/ui/api/queries?name=${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),
  logout: () => request("/logout", { method: "POST" }),
};
