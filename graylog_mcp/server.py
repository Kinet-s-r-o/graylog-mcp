from __future__ import annotations

import json
import logging
import base64
import hmac
import secrets
import string
import time
from contextvars import ContextVar
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from mcp.server.fastmcp import FastMCP
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .catalog import QueryCatalog
from .config import Settings
from .graylog import GraylogClient, GraylogError
from .openai_agent import OpenAIAgent
from .audit import AuditStore

settings = Settings()
logging.basicConfig(level=settings.log_level)
audit = AuditStore(settings.audit_db_path, settings.audit_retention_days, settings.audit_max_rows, settings.audit_max_payload_chars)
clients: dict[int, GraylogClient] = {}
agent_context: ContextVar[dict | None] = ContextVar("agent_context", default=None)
bearer = HTTPBearer(auto_error=False)
catalog = QueryCatalog(settings.query_catalog_path)
UI_SESSION_COOKIE = "graylog_ui_session"
UI_SESSION_TTL = 8 * 60 * 60
ui_sessions: dict[str, float] = {}

TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "search_messages", "description": "Search Graylog messages using a Lucene query", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "aggregate", "description": "Aggregate Graylog data by fields and metrics", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "group_by": {"type": "array", "items": {"type": "object"}}, "metrics": {"type": "array", "items": {"type": "object"}}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "list_saved_queries", "description": "List custom queries from the query catalog", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "run_saved_query", "description": "Run a managed Graylog query template by name", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "parameters": {"type": "object"}}, "required": ["name"]}}},
]

mcp = FastMCP("custom-graylog", host=settings.mcp_host, port=settings.mcp_port,
              streamable_http_path=settings.mcp_path)

class SearchRequest(BaseModel):
    query: str = Field(..., description="Graylog Lucene query")
    minutes: int = Field(15, ge=1, description="Relative time window in minutes")
    limit: int | None = Field(None, ge=1, description="Maximum number of messages")
    fields: list[str] | None = None

class AggregateRequest(BaseModel):
    query: str = Field(..., description="Graylog Lucene query")
    minutes: int = Field(60, ge=1)
    group_by: list[dict[str, Any]] = Field(default_factory=list, description="Graylog group_by definitions")
    metrics: list[dict[str, Any]] | None = None
    interval: str | None = Field(None, description="Optional time bucket, for example 5m")

class SavedQueryRequest(BaseModel):
    name: str
    parameters: dict[str, Any] = Field(default_factory=dict)

class ServerRequest(BaseModel):
    name: str
    url: str
    api_token: str
    verify_tls: bool = True
    timeout_seconds: float = Field(30, gt=0)

class AgentRequest(BaseModel):
    name: str
    graylog_server_id: int
    api_key: str | None = None

@asynccontextmanager
async def api_lifespan(_app):
    await audit.open()
    await audit.seed_queries(catalog.queries)
    yield
    await audit.close()
    for graylog_client in clients.values(): await graylog_client.close()
    clients.clear()

api = FastAPI(title="Custom Graylog MCP API", version="0.1.0",
              description="REST API for Graylog searches, aggregations and saved queries.", lifespan=api_lifespan)

def _render_query_value(value: Any, parameters: dict[str, Any]):
    if isinstance(value, str): return string.Template(value).safe_substitute(parameters)
    if isinstance(value, list): return [_render_query_value(item, parameters) for item in value]
    if isinstance(value, dict): return {key: _render_query_value(item, parameters) for key, item in value.items()}
    return value

async def render_saved_query(name: str, parameters: dict[str, Any]):
    definition = await audit.get_query(name)
    if not definition: raise KeyError(f"Unknown saved query '{name}'")
    values = {**definition.get("defaults", {}), **parameters}
    return _render_query_value(definition, values)

async def query_summaries():
    return [{"name": item["name"], "description": item.get("description", ""),
             "type": item.get("type", "messages"), "instructions": item.get("instructions", "")}
            for item in await audit.list_queries()]

async def get_client(server_id: int | None = None) -> GraylogClient:
    context = agent_context.get()
    selected_id = server_id or (context or {}).get("graylog_server_id")
    if not selected_id:
        raise HTTPException(status_code=403, detail="No Graylog server is assigned to this client")
    server = await audit.get_server(int(selected_id))
    if not server: raise HTTPException(status_code=404, detail="Graylog server not found")
    if int(selected_id) not in clients:
        clients[int(selected_id)] = GraylogClient(settings, audit, server=server)
    return clients[int(selected_id)]

async def require_agent(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not credentials: raise HTTPException(status_code=401, detail="Bearer API key required")
    context = await audit.authenticate_agent(credentials.credentials)
    if not context: raise HTTPException(status_code=401, detail="Invalid or inactive agent API key")
    agent_context.set(context)
    return context

@api.middleware("http")
async def mcp_authentication(request: Request, call_next):
    if request.url.path.startswith(settings.mcp_path):
        value = request.headers.get("authorization", "")
        context = await audit.authenticate_agent(value.split(" ", 1)[1].strip()) if value.lower().startswith("bearer ") else None
        if not context: return PlainTextResponse("Valid agent Bearer API key required", status_code=401)
        token = agent_context.set(context)
        try: return await call_next(request)
        finally: agent_context.reset(token)
    return await call_next(request)

@api.get("/health", tags=["System"])
async def api_health():
    return {"status": "ok", "service": "custom-graylog-mcp"}

@api.post("/api/v1/search/messages", tags=["Graylog"])
async def api_search_messages(body: SearchRequest, _agent=Depends(require_agent)):
    client = await get_client(); return await client.search_messages(body.query, body.minutes, body.limit or settings.graylog_default_limit, body.fields)

@api.post("/api/v1/search/aggregate", tags=["Graylog"])
async def api_aggregate(body: AggregateRequest, _agent=Depends(require_agent)):
    client = await get_client(); return await client.aggregate(body.query, body.minutes, body.group_by, body.metrics, body.interval)

@api.get("/api/v1/streams", tags=["Graylog"])
async def api_streams(_agent=Depends(require_agent)):
    return await (await get_client()).streams()

@api.get("/api/v1/queries", tags=["Saved queries"])
async def api_queries():
    return {"queries": await query_summaries()}

@api.post("/api/v1/queries/run", tags=["Saved queries"])
async def api_run_query(body: SavedQueryRequest, _agent=Depends(require_agent)):
    try: q = await render_saved_query(body.name, body.parameters)
    except KeyError as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc
    if q.get("type", "messages") == "aggregate":
        return await (await get_client()).aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval"))
    return await (await get_client()).search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))

@api.get("/api/v1/audit", tags=["Audit"])
async def api_audit(q: str | None = Query(None, description="FTS5 fulltext expression"), source: str | None = None,
                    limit: int = Query(25, ge=1, le=500), page: int = Query(1, ge=1), _agent=Depends(require_agent)):
    total = await audit.count_recent(q, source)
    return {"items": await audit.recent(limit, q, source, (page - 1) * limit),
            "total": total, "page": page, "page_size": limit,
            "pages": max(1, (total + limit - 1) // limit)}

METRICS_REFERENCE_HTML = """<section><h2>Graylog Metrics JSON reference</h2><p>Use a JSON array. You can combine multiple metrics in one request. The <code>field</code> must be a numeric or otherwise suitable field from your Graylog messages, except for <code>count</code>. The optional <code>sort</code> value can be <code>asc</code> or <code>desc</code>.</p><table><tr><th>Function</th><th>Purpose</th><th>Example</th></tr><tr><td><code>count</code></td><td>Counts matching messages. No field is required.</td><td><code>[{"function":"count"}]</code></td></tr><tr><td><code>average</code></td><td>Arithmetic average of a numeric field.</td><td><code>[{"function":"average","field":"response_ms"}]</code></td></tr><tr><td><code>latest</code></td><td>Latest value of a field in the matching data.</td><td><code>[{"function":"latest","field":"status_code"}]</code></td></tr><tr><td><code>max</code></td><td>Highest value of a numeric field.</td><td><code>[{"function":"max","field":"response_ms"}]</code></td></tr><tr><td><code>min</code></td><td>Lowest value of a numeric field.</td><td><code>[{"function":"min","field":"response_ms"}]</code></td></tr><tr><td><code>percentile</code></td><td>Percentile of a numeric field; configure it in <code>configuration</code>.</td><td><code>[{"function":"percentile","field":"response_ms","configuration":{"percentile":95}}]</code></td></tr><tr><td><code>stdDev</code></td><td>Standard deviation of a numeric field.</td><td><code>[{"function":"stdDev","field":"response_ms"}]</code></td></tr><tr><td><code>sum</code></td><td>Total of a numeric field.</td><td><code>[{"function":"sum","field":"bytes"}]</code></td></tr><tr><td><code>sumOfSquares</code></td><td>Sum of squared values of a numeric field.</td><td><code>[{"function":"sumOfSquares","field":"response_ms"}]</code></td></tr><tr><td><code>variance</code></td><td>Variance of a numeric field.</td><td><code>[{"function":"variance","field":"response_ms"}]</code></td></tr></table><h3>Combined example</h3><pre>[{"function":"count","id":"requests"},{"function":"average","field":"response_ms","id":"avg_response"},{"function":"percentile","field":"response_ms","configuration":{"percentile":95},"id":"p95_response"},{"function":"max","field":"response_ms","id":"max_response"}]</pre><p class="muted">Metric support and field availability depend on the Graylog version and the fields present in your messages. If a metric fails, verify the function spelling and field type.</p></section>"""

DOCS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graylog MCP UI documentation</title><style>
:root{font-family:system-ui,sans-serif;color:#17202a;background:#f5f7fa;line-height:1.5}body{margin:0}header{background:#102a43;color:#fff;padding:1rem}header .wrap,main{max-width:1100px;margin:auto}header .wrap{display:flex;align-items:center;justify-content:space-between;gap:1rem}header a{color:#dbeafe;text-decoration:none;border:1px solid #547493;border-radius:6px;padding:.45rem .7rem}.hero,section{background:#fff;border:1px solid #d9e0e7;border-radius:10px;padding:1.25rem;margin:1rem 0;box-shadow:0 2px 8px #0001}h1,h2{margin-top:0}h1{font-size:1.8rem}.muted{color:#64748b}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}.card{border:1px solid #d9e0e7;border-radius:8px;padding:1rem}.card h3{margin-top:0;color:#102a43}code,pre{font-family:ui-monospace,monospace}code{background:#edf2f7;padding:.1rem .3rem;border-radius:3px}pre{background:#111827;color:#d1fae5;padding:1rem;border-radius:6px;overflow:auto;white-space:pre-wrap}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d9e0e7;padding:.65rem}th{background:#edf2f7}@media(max-width:700px){main{padding:0 .7rem}.hero,section{padding:.9rem}table{font-size:.9rem}th,td{padding:.45rem}}
</style></head><body><header><div class="wrap"><strong>Graylog MCP</strong><a href="/">← Back to UI</a></div></header><main>
<div class="hero"><h1>Web UI documentation</h1><p class="muted">This guide explains every UI section, field, action, expected format, and the equivalent REST examples. The UI itself is protected by a session-based login form.</p><p><strong>Base URL:</strong> <code>http://localhost:8000</code> &nbsp; <strong>Admin login:</strong> the configured <code>UI_USERNAME</code> and <code>UI_PASSWORD</code>.</p></div>
<section><h2>1. Graylog Servers</h2><p>Add a Graylog server, select an existing one, test its API connection, or update its settings. Query execution and newly created agents use the selected server.</p><table><tr><th>Field / action</th><th>What to enter or expect</th></tr><tr><td><strong>Name</strong></td><td>A local label, for example <code>production</code> or <code>staging</code>.</td></tr><tr><td><strong>URL</strong></td><td>The Graylog base URL, for example <code>https://graylog.example.com</code>. Do not add <code>/api/cluster</code>; the UI adds the API path.</td></tr><tr><td><strong>API token</strong></td><td>Graylog API token. It is sent as Basic Auth in the <code>TOKEN:token</code> format. When editing, leave this blank to keep the stored token.</td></tr><tr><td><strong>Verify TLS</strong></td><td>Choose <code>yes</code> for normal HTTPS certificate verification. Choose <code>no</code> only for a trusted test environment with a self-signed certificate.</td></tr><tr><td><strong>Timeout (seconds)</strong></td><td>Positive connection/request timeout. Start with <code>30</code>; increase it for a slow or remote Graylog instance.</td></tr><tr><td><strong>Test connection</strong></td><td>Calls Graylog <code>GET /api/cluster</code> using the values currently in the form. It does not save changes.</td></tr><tr><td><strong>Add server</strong></td><td>Saves a new server configuration in SQLite.</td></tr><tr><td><strong>Save changes</strong></td><td>Updates the selected server. Blank API token preserves the existing token.</td></tr><tr><td><strong>Existing server</strong></td><td>Select a saved server to load its editable values. The token is never filled back into the form.</td></tr></table><p><strong>Connection errors:</strong> the result identifies the endpoint and provides details for timeout, TCP/DNS/port, TLS, or Graylog HTTP/API errors. Tokens are not included in the displayed URL.</p></section>
<section><h2>2. MCP Clients / Agents</h2><p>Each client is permanently restricted to one selected Graylog server. Use the generated key as the Bearer token for MCP or REST agent requests.</p><table><tr><th>Field / action</th><th>What to enter or expect</th></tr><tr><td><strong>Client name</strong></td><td>A recognizable name, for example <code>grafana-agent</code> or <code>monitoring-agent</code>.</td></tr><tr><td><strong>API key (optional)</strong></td><td>Leave blank to generate a secure key, or provide your own key. The raw key is shown only after creation.</td></tr><tr><td><strong>Add client</strong></td><td>Creates the agent for the currently selected Graylog server. Store the returned key immediately; only its hash and last four characters are retained.</td></tr></table><pre>curl -H "Authorization: Bearer AGENT_API_KEY" http://localhost:8000/mcp</pre></section>
<section><h2>3. Query Rules</h2><p>Query rules are reusable definitions stored in SQLite. They can be used by MCP agents through <code>run_saved_query</code>.</p><table><tr><th>Field</th><th>What to enter</th></tr><tr><td><strong>Existing rule</strong></td><td>Select an existing rule to edit. Use <strong>New rule</strong> to clear the form.</td></tr><tr><td><strong>Name</strong></td><td>Unique rule name, for example <code>errors_by_service</code>.</td></tr><tr><td><strong>Description</strong></td><td>Short explanation shown to agents and administrators.</td></tr><tr><td><strong>Type</strong></td><td><code>messages</code> returns matching messages; <code>aggregate</code> returns grouped metrics.</td></tr><tr><td><strong>Time range (minutes)</strong></td><td>Positive relative time window, for example <code>60</code>.</td></tr><tr><td><strong>Message limit</strong></td><td>Maximum messages for message search, for example <code>100</code>. The server applies its configured maximum.</td></tr><tr><td><strong>Time bucket</strong></td><td>Optional Graylog time unit for aggregation, for example <code>5m</code>, <code>1h</code>, or <code>1d</code>.</td></tr><tr><td><strong>Lucene query template</strong></td><td>Graylog/Lucene query, for example <code>service:${service} AND level:3</code>. Template variables use <code>${name}</code>.</td></tr><tr><td><strong>Group by JSON</strong></td><td>JSON array of grouping objects, for example <code>[{"field":"service"}]</code>. Use <code>[]</code> for no grouping.</td></tr><tr><td><strong>Metrics JSON</strong></td><td>JSON array of Graylog metrics, for example <code>[{"function":"count"}]</code>.</td></tr><tr><td><strong>Default parameters JSON</strong></td><td>JSON object for template defaults, for example <code>{"service":"api"}</code>.</td></tr><tr><td><strong>Instructions for the agent</strong></td><td>Plain-language guidance about when and how the rule should be used.</td></tr><tr><td><strong>Save / New / Delete rule</strong></td><td>Validate and persist, clear for a new rule, or permanently remove the selected rule.</td></tr></table><pre>curl -X POST http://localhost:8000/api/v1/queries/run \
  -H "Authorization: Bearer AGENT_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"errors_by_service","parameters":{"service":"api"}}'</pre></section>
<section><h2>4. Run a Graylog query</h2><p>The first section also provides direct, one-off query controls. Choose <strong>Message search</strong>, <strong>Aggregation</strong>, or <strong>Managed query</strong>.</p><div class="grid"><div class="card"><h3>Message search</h3><p>Enter a Lucene query, time range, and message limit. Example query: <code>level:3 OR service:api</code>.</p></div><div class="card"><h3>Aggregation</h3><p>Enter a Lucene query, comma-separated grouping fields such as <code>service,source</code>, and metrics JSON such as <code>[{"function":"count"}]</code>.</p></div><div class="card"><h3>Managed query</h3><p>Select a saved Query Rule. Its stored query, parameters, grouping, metrics, and limits are used.</p></div></div><p><strong>Run query</strong> sends the request to the selected server. <strong>Load streams</strong> lists Graylog streams for that server. Results appear in the output panel.</p><pre>curl -X POST http://localhost:8000/api/v1/search/messages \
  -H "Authorization: Bearer AGENT_API_KEY" -H "Content-Type: application/json" \
  -d '{"query":"level:3 OR service:api","minutes":15,"limit":20}'

curl -X POST http://localhost:8000/api/v1/search/aggregate \
  -H "Authorization: Bearer AGENT_API_KEY" -H "Content-Type: application/json" \
  -d '{"query":"*","minutes":60,"group_by":[{"field":"service"}],"metrics":[{"function":"count"}]}'</pre></section>
<section><h2>5. Audit Log</h2><p>Searches recorded UI/API activity and Graylog calls stored in the SQLite audit database.</p><table><tr><th>Field / action</th><th>What to enter or expect</th></tr><tr><td><strong>Full-text search</strong></td><td>FTS5 expression. Examples: <code>authentication OR timeout</code>, a phrase such as <code>"connection failed"</code>, or a prefix such as <code>error*</code>.</td></tr><tr><td><strong>Source</strong></td><td>Filter by <code>graylog</code>, <code>openai</code>, or <code>mcp</code>; leave <code>All sources</code> to include everything.</td></tr><tr><td><strong>Search audit log</strong></td><td>Runs the search and prints matching records as JSON.</td></tr></table><pre>curl "http://localhost:8000/api/v1/audit?q=authentication%20OR%20timeout&amp;source=graylog&amp;limit=100" \
  -H "Authorization: Bearer AGENT_API_KEY"</pre></section>
<section><h2>6. REST and system commands</h2><p>The REST API is under <code>/api/v1</code>. The interactive API reference is available at <a href="/docs">/docs</a> and the OpenAPI schema at <a href="/openapi.json">/openapi.json</a>.</p><pre>curl http://localhost:8000/health

curl http://localhost:8000/api/v1/streams \
  -H "Authorization: Bearer AGENT_API_KEY"

curl http://localhost:8000/api/v1/queries \
  -H "Authorization: Bearer AGENT_API_KEY"</pre><p>For Docker, start or rebuild with <code>docker compose up -d --build</code>. The UI is at <code>http://localhost:8000/</code>; replace the host and port if <code>MCP_PORT</code> is changed.</p></section>
</main></body></html>"""

DOCS_HTML = DOCS_HTML.replace(
    '<section><h2>3. Query Rules</h2>',
    '<section><h2>3. Query Rules</h2><div class="card"><h3>How template variables work</h3><p><code>${service}</code> is a placeholder, not a built-in Graylog variable and not an automatically detected field. You choose the variable name yourself. In <code>service:${service} AND level:3</code>, the value is inserted before the query is sent to Graylog.</p><ol><li>Put a placeholder in the query using <code>${name}</code>. Use letters, numbers, and underscores; start with a letter or underscore.</li><li>Set an optional fallback in <strong>Default parameters JSON</strong>, for example <code>{"service":"api"}</code>.</li><li>Supply or override the value when calling <code>run_saved_query</code>, for example <code>{"service":"web"}</code>. Call-time values take precedence over defaults.</li></ol><p>There is no fixed list of variable names. Use descriptive names such as <code>service</code>, <code>host</code>, <code>environment</code>, or <code>status</code>. The direct <strong>Graylog query (Lucene)</strong> field is sent as-is and does not substitute variables.</p></div>'
)

DOCS_HTML = DOCS_HTML.replace('<section><h2>4. Run a Graylog query</h2>', METRICS_REFERENCE_HTML + '<section><h2>4. Run a Graylog query</h2>')
DOCS_HTML = DOCS_HTML.replace('Each client is permanently restricted to one selected Graylog server.', 'Each client is restricted to one selected Graylog server and can later be reassigned in the UI.')

UI_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graylog MCP</title><style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fa;color:#17202a;transition:background .2s,color .2s}
header{position:sticky;top:0;z-index:1000;background:#102a43;color:#fff;box-shadow:0 2px 8px #0004}.nav-wrap{max-width:1100px;margin:auto;display:flex;align-items:center;justify-content:space-between;padding:.7rem 1rem}.brand{font-weight:700}.nav-toggle{display:none;background:#244f78;color:#fff;margin:0}.nav-links{display:flex;gap:.4rem}.nav-links a{color:#dbeafe;text-decoration:none;padding:.5rem .7rem;border-radius:5px}.nav-links a.active,.nav-links a:hover{background:#2563eb;color:#fff}.help-link{display:inline-flex;align-items:center;justify-content:center;width:1.8rem;height:1.8rem;padding:0!important;border:1px solid #dbeafe;border-radius:50%!important;font-weight:700}
main{max-width:1100px;margin:2rem auto;padding:0 1rem}.page-section{display:none;background:white;border:1px solid #d9e0e7;border-radius:10px;padding:1.25rem;box-shadow:0 2px 8px #0001;transition:background .2s,border-color .2s}.page-section.active{display:block}
label{display:block;font-weight:600;margin:.8rem 0 .25rem}input,select,textarea,button{font:inherit;padding:.55rem;border:1px solid #b8c3ce;border-radius:5px;box-sizing:border-box;width:100%}
textarea{min-height:90px;font-family:ui-monospace,monospace}button{width:auto;background:#2563eb;color:white;border:0;cursor:pointer;margin-top:1rem}button.secondary{background:#566573}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:700px){.grid{grid-template-columns:1fr}}
pre{background:#111827;color:#d1fae5;padding:1rem;border-radius:6px;overflow:auto;min-height:180px}.muted{color:#64748b}.status-message{white-space:pre-line}.field-help{display:inline-flex;position:relative;align-items:center;justify-content:center;width:1.15rem;height:1.15rem;margin-left:.25rem;border:1px solid #64748b;border-radius:50%;font-size:.75rem;font-weight:700;color:#475569;cursor:help;vertical-align:middle}.field-help .tooltip{visibility:hidden;opacity:0;position:absolute;z-index:20;left:1.5rem;top:-.25rem;width:260px;padding:.55rem .7rem;background:#17202a;color:#fff;border-radius:6px;font-size:.82rem;font-weight:400;line-height:1.35;box-shadow:0 3px 10px #0004;transition:opacity .15s}.field-help:hover .tooltip,.field-help:focus .tooltip{visibility:visible;opacity:1}.theme{background:#e2e8f0;color:#17202a;margin:0}.nav-links{margin-left:auto}.nav-wrap{gap:.5rem}
body.dark{background:#071426;color:#e5eefb}body.dark .page-section{background:#0d2138;border-color:#1e456d}body.dark input,body.dark select,body.dark textarea{background:#102b48;color:#e5eefb;border-color:#32618e}body.dark .muted{color:#9db4cc}body.dark .field-help{color:#c5d8ed;border-color:#9db4cc}body.dark .theme{background:#21476e;color:#e5eefb}
@media(max-width:700px){main{margin:1rem auto;padding:0 .7rem}.nav-toggle{display:block}.nav-links{display:none;position:absolute;top:3.3rem;left:0;right:0;background:#102a43;flex-direction:column;padding:.5rem 1rem;box-shadow:0 4px 8px #0003}.nav-links.open{display:flex}.nav-wrap{position:relative}.page-section{padding:.9rem}.grid{grid-template-columns:1fr}h1{font-size:1.45rem}h2{font-size:1.2rem}}
</style></head><body><header><div class="nav-wrap"><div class="brand">Graylog MCP</div><button class="nav-toggle" onclick="toggleMenu()" aria-label="Open menu">☰ Menu</button><nav class="nav-links" id="navLinks"><a href="#graylog" data-section="graylogSection">Graylog Servers</a><a href="#clients" data-section="clientsSection">MCP Clients</a><a href="#queries" data-section="queriesSection">Query Rules</a><a href="#audit" data-section="auditSection">Audit Log</a></nav><a class="help-link" href="/ui/help" target="_blank" rel="noopener" title="Open UI documentation" aria-label="Open UI documentation">?</a><button class="theme" onclick="toggleTheme()" id="themeButton">Dark mode</button></div></header><main>
<section id="graylogSection" class="page-section active"><h2>Graylog Servers</h2><div class="grid"><div><label>Name</label><input id="serverName" placeholder="production"></div><div><label>URL</label><input id="serverUrl" placeholder="https://graylog.example.com"></div><div><label>API token</label><input id="serverToken" type="password" placeholder="leave blank when editing to keep the current token"></div><div><label>Verify TLS</label><select id="serverTls"><option value="true">yes</option><option value="false">no</option></select></div><div><label>Timeout (seconds)</label><input id="serverTimeout" type="number" value="30" min="1"></div></div><button onclick="testServer()" class="secondary">Test connection</button> <button onclick="addServer()">Add server</button> <button onclick="updateServer()">Save changes</button> <label>Existing server</label><select id="serverId" onchange="selectServer()"></select> <button class="secondary" onclick="loadServers()">Refresh servers</button><p id="serverStatus" class="muted status-message"></p>
<label>Query type</label><select id="kind"><option value="search">Message search</option><option value="aggregate">Aggregation</option><option value="saved">Managed query</option></select>
<label id="savedLabel" hidden>Managed query</label><select id="saved" hidden></select>
<label>Graylog query (Lucene) <span class="field-help" tabindex="0" aria-label="Lucene query example">?<span class="tooltip">Example: <code>level:3 OR service:api</code><br>Use Lucene operators such as <code>AND</code>, <code>OR</code>, quotes, and field filters.</span></span></label><textarea id="query" placeholder="level:3 OR service:api"></textarea>
<div class="grid"><div><label>Time range (minutes)</label><input id="minutes" type="number" value="60" min="1"></div><div><label>Message limit</label><input id="limit" type="number" value="100" min="1"></div></div>
<label>Group by (aggregation only, comma-separated)</label><input id="groupBy" placeholder="service,source">
<label>Metrics JSON (aggregation only)</label><input id="metrics" value='[{"function":"count"}]'>
<button onclick="run()">Run query</button> <button class="secondary" onclick="loadStreams()">Load streams</button>
<h2>Result</h2><pre id="out">Ready.</pre></section>
<section id="clientsSection" class="page-section"><h2>MCP Clients / Agents</h2><p class="muted">Each client is restricted to one Graylog server. The API key is displayed only when the client is created.</p><div class="grid"><div><label>Client name</label><input id="agentName" placeholder="monitoring-agent"></div><div><label>API key (optional)</label><input id="agentKey" type="password" placeholder="leave blank to generate"></div></div><button onclick="addAgent()">Add client</button><pre id="agentOut">A newly generated API key will be shown here once.</pre></section>
<section id="queriesSection" class="page-section"><h2>MCP Query Rules</h2><p class="muted">Define reusable filters and aggregation behavior available to MCP agents.</p><label>Existing rule</label><select id="ruleId" onchange="selectRule()"></select><div class="grid"><div><label>Name</label><input id="ruleName" placeholder="errors_by_service"></div><div><label>Description</label><input id="ruleDescription" placeholder="Count errors grouped by service"></div><div><label>Type</label><select id="ruleType"><option value="messages">Message search</option><option value="aggregate">Aggregation</option></select></div><div><label>Time range (minutes)</label><input id="ruleMinutes" type="number" value="60" min="1"></div><div><label>Message limit</label><input id="ruleLimit" type="number" value="100" min="1"></div><div><label>Time bucket</label><input id="ruleInterval" placeholder="5m"></div></div><label>Lucene query template <span class="field-help" tabindex="0" aria-label="Lucene template example">?<span class="tooltip">Example: <code>service:${service} AND level:3</code><br>Template values use the <code>${name}</code> syntax.</span></span></label><textarea id="ruleQuery" placeholder="service:${service} AND level:3"></textarea><label>Group by JSON <span class="field-help" tabindex="0" aria-label="Group by JSON example">?<span class="tooltip">Example: <code>[{"field":"service"}]</code><br>Use <code>[]</code> when no grouping is needed.</span></span></label><textarea id="ruleGroup">[]</textarea><label>Metrics JSON <span class="field-help" tabindex="0" aria-label="Metrics JSON example">?<span class="tooltip">Example: <code>[{"function":"count"}]</code><br>Graylog metric definitions must be a JSON array.</span></span></label><textarea id="ruleMetrics">[{"function":"count"}]</textarea><label>Default parameters JSON <span class="field-help" tabindex="0" aria-label="Default parameters JSON example">?<span class="tooltip">Example: <code>{"service":"api"}</code><br>These values are used when a template parameter is not supplied.</span></span></label><textarea id="ruleDefaults">{}</textarea><label>Instructions for the agent <span class="field-help" tabindex="0" aria-label="Agent instructions example">?<span class="tooltip">Example: <code>Use this rule for error counts grouped by service.</code><br>Explain when the agent should select this rule.</span></span></label><textarea id="ruleInstructions" placeholder="Use this rule when the user asks for error counts by service."></textarea><button onclick="saveRule()">Save rule</button> <button class="secondary" onclick="newRule()">New rule</button> <button class="secondary" onclick="deleteRule()">Delete rule</button><p id="ruleStatus" class="muted"></p></section>
<section id="auditSection" class="page-section"><h2>Audit Log</h2><div class="grid"><div><label>Full-text search</label><input id="auditSearch" placeholder="for example: authentication OR timeout"></div><div><label>Source</label><select id="auditSource"><option value="">All sources</option><option>graylog</option><option>openai</option><option>mcp</option></select></div></div><button class="secondary" onclick="loadAudit()">Search audit log</button><pre id="auditOut">Run a search to load audit records.</pre></section></main><script>
const $=id=>document.getElementById(id);let queryItems=[];async function loadSaved(){let r=await fetch('/ui/api/queries');let d=await r.json();queryItems=d.queries||[];$('saved').innerHTML=queryItems.map(x=>`<option value="${x.name}">${x.name} — ${x.description||''}</option>`).join('');$('ruleId').innerHTML=queryItems.map(x=>`<option value="${x.name}">${x.name}</option>`).join('');selectRule()}
$('kind').onchange=()=>{let s=$('kind').value==='saved';$('saved').hidden=!s;$('savedLabel').hidden=!s};loadSaved();
let serverItems=[];
async function loadServers(){let r=await fetch('/ui/api/servers');let d=await r.json();serverItems=d.items||[];$('serverId').innerHTML=serverItems.map(x=>`<option value="${x.id}">${x.name} (${x.url})</option>`).join('');selectServer()}
function selectServer(){let s=serverItems.find(x=>x.id===+$('serverId').value);if(!s)return;$('serverName').value=s.name;$('serverUrl').value=s.url;$('serverToken').value='';$('serverTls').value=s.verify_tls?'true':'false';$('serverTimeout').value=s.timeout_seconds||30}
function serverPayload(){return{name:$('serverName').value,url:$('serverUrl').value,api_token:$('serverToken').value,verify_tls:$('serverTls').value==='true',timeout_seconds:+$('serverTimeout').value||30}}
async function addServer(){let r=await fetch('/ui/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(serverPayload())});$('out').textContent=JSON.stringify(await r.json(),null,2);await loadServers()}
async function updateServer(){let b=serverPayload();b.server_id=+$('serverId').value;let r=await fetch('/ui/api/servers',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});let d=await r.json();$('serverStatus').textContent=r.ok?'✓ Changes saved.':'✗ '+(d.detail||'Save failed.');$('serverStatus').style.color=r.ok?'#15803d':'#b91c1c';await loadServers()}
async function testServer(){let b=serverPayload();b.server_id=+$('serverId').value;$('serverStatus').textContent='Testing connection...';let r=await fetch('/ui/api/servers/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});let d=await r.json();$('serverStatus').textContent=(d.success?'✓ ':'✗ ')+(d.message||d.detail);$('serverStatus').style.color=d.success?'#15803d':'#b91c1c'}
async function addAgent(){let b={name:$('agentName').value,graylog_server_id:+$('serverId').value};if($('agentKey').value)b.api_key=$('agentKey').value;let r=await fetch('/ui/api/agents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('agentOut').textContent=JSON.stringify(await r.json(),null,2)}
async function run(){let k=$('kind').value,b={server_id:+$('serverId').value};if(k==='saved'){b={...b,name:$('saved').value,parameters:{}}}else if(k==='search'){b={...b,query:$('query').value,minutes:+$('minutes').value,limit:+$('limit').value}}else{try{b={...b,query:$('query').value,minutes:+$('minutes').value,group_by:$('groupBy').value.split(',').map(x=>x.trim()).filter(Boolean).map(field=>({field})),metrics:JSON.parse($('metrics').value)}}catch(e){$('out').textContent='Invalid metrics JSON: '+e;return}};let r=await fetch('/ui/api/'+(k==='saved'?'saved':'query'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadStreams(){let r=await fetch('/ui/api/streams?server_id='+$('serverId').value);$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadAudit(){let p=new URLSearchParams();if($('auditSearch').value)p.set('q',$('auditSearch').value);if($('auditSource').value)p.set('source',$('auditSource').value);let r=await fetch('/ui/api/audit?'+p);$('auditOut').textContent=JSON.stringify(await r.json(),null,2)}
function newRule(){$('ruleName').value='';$('ruleDescription').value='';$('ruleType').value='messages';$('ruleMinutes').value=60;$('ruleLimit').value=100;$('ruleInterval').value='';$('ruleQuery').value='';$('ruleGroup').value='[]';$('ruleMetrics').value='[{"function":"count"}]';$('ruleDefaults').value='{}';$('ruleInstructions').value='';$('ruleStatus').textContent='Creating a new rule.'}
function selectRule(){let q=queryItems.find(x=>x.name===$('ruleId').value);if(!q)return;$('ruleName').value=q.name;$('ruleDescription').value=q.description||'';$('ruleType').value=q.type||'messages';$('ruleMinutes').value=q.minutes||60;$('ruleLimit').value=q.limit||100;$('ruleInterval').value=q.interval||'';$('ruleQuery').value=q.query||'';$('ruleGroup').value=JSON.stringify(q.group_by||[],null,2);$('ruleMetrics').value=JSON.stringify(q.metrics||[{function:'count'}],null,2);$('ruleDefaults').value=JSON.stringify(q.defaults||{},null,2);$('ruleInstructions').value=q.instructions||''}
async function saveRule(){try{let b={name:$('ruleName').value.trim(),description:$('ruleDescription').value,type:$('ruleType').value,query:$('ruleQuery').value,minutes:+$('ruleMinutes').value,limit:+$('ruleLimit').value,interval:$('ruleInterval').value,group_by:JSON.parse($('ruleGroup').value),metrics:JSON.parse($('ruleMetrics').value),defaults:JSON.parse($('ruleDefaults').value),instructions:$('ruleInstructions').value};let r=await fetch('/ui/api/queries',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});let d=await r.json();$('ruleStatus').textContent=r.ok?'✓ Rule saved.':'✗ '+(d.detail||'Save failed.');if(r.ok)await loadSaved()}catch(e){$('ruleStatus').textContent='✗ Invalid JSON: '+e}}
async function deleteRule(){let name=$('ruleId').value;if(!name)return;let r=await fetch('/ui/api/queries?name='+encodeURIComponent(name),{method:'DELETE'});$('ruleStatus').textContent=r.ok?'✓ Rule deleted.':'✗ Delete failed.';await loadSaved()}
function setTheme(dark){document.body.classList.toggle('dark',dark);$('themeButton').textContent=dark?'Light mode':'Dark mode';localStorage.setItem('graylog-mcp-theme',dark?'dark':'light')}
function toggleTheme(){setTheme(!document.body.classList.contains('dark'))}setTheme(localStorage.getItem('graylog-mcp-theme')==='dark');
function toggleMenu(){$('navLinks').classList.toggle('open')}
function showSection(id){document.querySelectorAll('.page-section').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.nav-links a').forEach(x=>x.classList.toggle('active',x.dataset.section===id));$('navLinks').classList.remove('open');if(id==='auditSection')loadAudit()}
document.querySelectorAll('.nav-links a').forEach(x=>x.onclick=e=>{e.preventDefault();history.replaceState(null,'','#'+x.getAttribute('href').slice(1));showSection(x.dataset.section)})
showSection(location.hash==='#clients'?'clientsSection':location.hash==='#queries'?'queriesSection':location.hash==='#audit'?'auditSection':'graylogSection');loadServers();
</script></body></html>"""

CLIENTS_SECTION_HTML = """<section id="clientsSection" class="page-section"><h2>MCP Clients / Agents</h2><p class="muted">Clients are stored in SQLite and can be edited or reassigned to another Graylog server. The full API key is shown only after creation or when you explicitly replace it.</p><label>Existing client</label><select id="agentId" onchange="selectAgent()"></select><div class="grid"><div><label>Client name</label><input id="agentName" placeholder="monitoring-agent"></div><div><label>Assigned Graylog server</label><select id="agentServer"></select></div><div><label>New API key (optional)</label><input id="agentKey" type="password" placeholder="leave blank to keep the current key"></div><div><label>Status</label><select id="agentActive"><option value="true">Active</option><option value="false">Inactive</option></select></div></div><button onclick="addAgent()">Add client</button> <button class="secondary" onclick="saveAgent()">Save changes</button> <button class="secondary" onclick="newAgent()">New client</button> <button class="secondary" onclick="deleteAgent()">Delete client</button><pre id="agentOut">Select a client or create a new one.</pre></section>"""
_clients_start = UI_HTML.index('<section id="clientsSection"')
_clients_end = UI_HTML.index('</section>', _clients_start) + len('</section>')
UI_HTML = UI_HTML[:_clients_start] + CLIENTS_SECTION_HTML + UI_HTML[_clients_end:]

AUDIT_SECTION_HTML = """<section id="auditSection" class="page-section"><div class="section-heading"><div><h2>Audit Log</h2><p class="muted">Browse every recorded request and response. Open a row to inspect the complete payload and error details.</p></div><span id="auditSummary" class="audit-summary"></span></div><div class="grid"><div><label>Full-text search</label><input id="auditSearch" placeholder="for example: authentication OR timeout"></div><div><label>Source</label><select id="auditSource"><option value="">All sources</option><option>graylog</option><option>openai</option><option>mcp</option></select></div></div><div class="audit-actions"><button class="secondary" onclick="loadAudit(1)">Search audit log</button><label class="audit-page-size">Rows per page <select id="auditPageSize" onchange="loadAudit(1)"><option value="10">10</option><option value="25" selected>25</option><option value="50">50</option><option value="100">100</option></select></label></div><div id="auditOut" class="audit-table-wrap"><p class="muted">Run a search to load audit records.</p></div><div class="audit-pagination"><button id="auditPrev" class="secondary" onclick="changeAuditPage(-1)">← Previous</button><span id="auditPageInfo" class="muted"></span><button id="auditNext" class="secondary" onclick="changeAuditPage(1)">Next →</button></div></section>"""
_audit_start = UI_HTML.index('<section id="auditSection"')
_audit_end = UI_HTML.index('</section>', _audit_start) + len('</section>')
UI_HTML = UI_HTML[:_audit_start] + AUDIT_SECTION_HTML + UI_HTML[_audit_end:]

MANAGEMENT_SECTIONS_HTML = """<section id="graylogSection" class="page-section active"><div class="section-heading"><div><h2>Graylog Servers</h2><p class="muted">Manage the Graylog connections used by MCP clients.</p></div><button onclick="openServerModal()">+ Add server</button></div><div id="serversOut" class="audit-table-wrap"><p class="muted">Loading servers…</p></div></section>
<section id="clientsSection" class="page-section"><div class="section-heading"><div><h2>MCP Clients / Agents</h2><p class="muted">Each client is restricted to one Graylog server. Full API keys are shown only after creation or replacement.</p></div><button onclick="openAgentModal()">+ Add client</button></div><div id="agentsOut" class="audit-table-wrap"><p class="muted">Loading clients…</p></div></section>
<section id="queriesSection" class="page-section"><div class="section-heading"><div><h2>MCP Query Rules</h2><p class="muted">Reusable filters and aggregation behavior available to MCP agents.</p></div><button onclick="openRuleModal()">+ Add rule</button></div><div id="queriesOut" class="audit-table-wrap"><p class="muted">Loading query rules…</p></div></section>"""
for _section_id in ("graylogSection", "clientsSection", "queriesSection"):
    _section_start = UI_HTML.index(f'<section id="{_section_id}"')
    _section_end = UI_HTML.index('</section>', _section_start) + len('</section>')
    _replacement = MANAGEMENT_SECTIONS_HTML.split('\n')[("graylogSection", "clientsSection", "queriesSection").index(_section_id)]
    UI_HTML = UI_HTML[:_section_start] + _replacement + UI_HTML[_section_end:]

MANAGEMENT_MODAL_HTML = """<div id="editModal" class="modal-backdrop" hidden onclick="if(event.target===this)closeModal()"><div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modalTitle"><div class="modal-header"><h2 id="modalTitle">Edit</h2><button class="modal-close" onclick="closeModal()" aria-label="Close">×</button></div><form id="editForm" onsubmit="return submitModal(event)"><div id="modalFields"></div><div id="modalStatus" class="muted status-message"></div><div class="modal-actions"><button type="button" class="secondary" id="testModalButton" onclick="testModalServer()" hidden>Test connection</button><button type="button" class="secondary" onclick="closeModal()">Cancel</button><button type="submit" id="modalSaveButton">Save</button></div></form></div></div>"""
UI_HTML = UI_HTML.replace('</main><script>', '</main>' + MANAGEMENT_MODAL_HTML + '<script>')

AGENT_JS = """async function loadAgents(){let r=await fetch('/ui/api/agents');let d=await r.json();agentItems=d.items||[];$(\"agentId\").innerHTML=agentItems.map(x=>`<option value=\"${x.id}\">${x.name} — ${x.graylog_server_name}</option>`).join(\"\");$(\"agentServer\").innerHTML=serverItems.map(x=>`<option value=\"${x.id}\">${x.name} (${x.url})</option>`).join(\"\");selectAgent()}function selectAgent(){let a=agentItems.find(x=>x.id===+$('agentId').value);if(!a){newAgent();return}$('agentName').value=a.name;$('agentServer').value=a.graylog_server_id;$('agentActive').value=a.active?'true':'false';$('agentKey').value=''}function newAgent(){$('agentId').value='';$('agentName').value='';$('agentServer').value=serverItems[0]?.id||'';$('agentActive').value='true';$('agentKey').value='';$('agentOut').textContent='Enter the client details and click Add client.'}async function saveAgent(){let b={agent_id:+$('agentId').value,name:$('agentName').value.trim(),graylog_server_id:+$('agentServer').value,active:$('agentActive').value==='true'};if($('agentKey').value)b.api_key=$('agentKey').value;let r=await fetch('/ui/api/agents',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('agentOut').textContent=JSON.stringify(await r.json(),null,2);if(r.ok)await loadAgents()}async function deleteAgent(){let id=+$('agentId').value;if(!id)return;$('agentOut').textContent=JSON.stringify(await (await fetch('/ui/api/agents?id='+id,{method:'DELETE'})).json(),null,2);await loadAgents()}"""

UI_HTML = UI_HTML.replace(
    'Template values use the <code>${name}</code> syntax.',
    'Values come from Default parameters JSON or run_saved_query parameters; call-time values override defaults. The direct query field does not substitute variables.'
)
UI_HTML = UI_HTML.replace(
    'Graylog metric definitions must be a JSON array.',
    'Available functions with examples:<br><code>count</code>: <code>[{"function":"count"}]</code><br><code>average</code>: <code>[{"function":"average","field":"response_ms"}]</code><br><code>latest</code>: <code>[{"function":"latest","field":"status_code"}]</code><br><code>max</code>: <code>[{"function":"max","field":"response_ms"}]</code><br><code>min</code>: <code>[{"function":"min","field":"response_ms"}]</code><br><code>percentile</code>: <code>[{"function":"percentile","field":"response_ms","configuration":{"percentile":95}}]</code><br><code>stdDev</code>: <code>[{"function":"stdDev","field":"response_ms"}]</code><br><code>sum</code>: <code>[{"function":"sum","field":"bytes"}]</code><br><code>sumOfSquares</code>: <code>[{"function":"sumOfSquares","field":"response_ms"}]</code><br><code>variance</code>: <code>[{"function":"variance","field":"response_ms"}]</code>'
)
UI_HTML = UI_HTML.replace('width:260px;', 'width:420px;')
for metric_name in ('average', 'latest', 'max', 'min', 'percentile', 'stdDev', 'sum', 'sumOfSquares', 'variance'):
    UI_HTML = UI_HTML.replace(f'<br><code>{metric_name}</code>:', f'<br><br><code>{metric_name}</code>:')
UI_HTML = UI_HTML.replace(
    '<label>Metrics JSON (aggregation only)</label>',
    '<label>Metrics JSON (aggregation only) <span class="field-help" tabindex="0" aria-label="Metrics JSON reference">?<span class="tooltip">Available functions with examples:<br><code>count</code> — messages: <code>[{"function":"count"}]</code><br><br><code>average</code> — numeric average: <code>[{"function":"average","field":"response_ms"}]</code><br><br><code>latest</code> — latest value: <code>[{"function":"latest","field":"status_code"}]</code><br><br><code>max</code> — highest value: <code>[{"function":"max","field":"response_ms"}]</code><br><br><code>min</code> — lowest value: <code>[{"function":"min","field":"response_ms"}]</code><br><br><code>percentile</code> — percentile: <code>[{"function":"percentile","field":"response_ms","configuration":{"percentile":95}}]</code><br><br><code>stdDev</code> — standard deviation: <code>[{"function":"stdDev","field":"response_ms"}]</code><br><br><code>sum</code> — numeric total: <code>[{"function":"sum","field":"bytes"}]</code><br><br><code>sumOfSquares</code> — squared total: <code>[{"function":"sumOfSquares","field":"response_ms"}]</code><br><br><code>variance</code> — variance: <code>[{"function":"variance","field":"response_ms"}]</code></span></span></label>'
)
UI_HTML = UI_HTML.replace(
    'async function addAgent()',
    AGENT_JS + 'async function addAgent()'
)
AUDIT_JS = """let auditPage=1;function auditEscape(value){return String(value??'—').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;')}function auditJson(value){if(value===null||value===undefined||value==='')return '—';try{return auditEscape(JSON.stringify(JSON.parse(value),null,2))}catch(e){return auditEscape(value)}}function renderAudit(data){auditPage=data.page||1;let pages=data.pages||1;$('auditSummary').textContent=`${data.total||0} records`;$('auditPageInfo').textContent=`Page ${auditPage} of ${pages}`;$('auditPrev').disabled=auditPage<=1;$('auditNext').disabled=auditPage>=pages;if(!data.items?.length){$('auditOut').innerHTML='<p class="audit-empty muted">No audit records found.</p>';return}$('auditOut').innerHTML='<table class="audit-table"><thead><tr><th>ID</th><th>Created</th><th>Source</th><th>Operation</th><th>Status</th><th>Duration</th><th>Result</th><th>Details</th></tr></thead><tbody>'+data.items.map(item=>`<tr><td>${auditEscape(item.id)}</td><td>${auditEscape(item.created_at)}</td><td>${auditEscape(item.source)}</td><td>${auditEscape(item.operation)}</td><td>${item.success?'✓ Success':'✗ Failed'}${item.status_code?`<br><small>${auditEscape(item.status_code)}</small>`:''}</td><td>${item.duration_ms===null||item.duration_ms===undefined?'—':auditEscape(Number(item.duration_ms).toFixed(1)+' ms')}</td><td class="${item.success?'success':'failed'}">${item.success?'Success':'Failed'}</td><td><details class="audit-detail"><summary>Request / response${item.error?' / error':''}</summary>${item.request_json?`<strong>Request</strong><pre>${auditJson(item.request_json)}</pre>`:''}${item.response_json?`<strong>Response</strong><pre>${auditJson(item.response_json)}</pre>`:''}${item.error?`<strong>Error</strong><pre>${auditEscape(item.error)}</pre>`:''}</details></td></tr>`).join('')+'</tbody></table>'}async function loadAudit(page=1){let p=new URLSearchParams({limit:$('auditPageSize').value,page});if($('auditSearch').value)p.set('q',$('auditSearch').value);if($('auditSource').value)p.set('source',$('auditSource').value);let r=await fetch('/ui/api/audit?'+p);let data=await r.json();if(!r.ok){$('auditOut').innerHTML=`<p class="audit-empty failed">${auditEscape(data.detail||'Audit log could not be loaded.')}</p>`;return}renderAudit(data)}function changeAuditPage(delta){loadAudit(auditPage+delta)}"""
UI_HTML = UI_HTML.replace('async function loadAudit()', AUDIT_JS + 'async function loadAudit()')
UI_HTML = UI_HTML.replace(
    "async function loadAudit(){let p=new URLSearchParams();if($('auditSearch').value)p.set('q',$('auditSearch').value);if($('auditSource').value)p.set('source',$('auditSource').value);let r=await fetch('/ui/api/audit?'+p);$('auditOut').textContent=JSON.stringify(await r.json(),null,2)}",
    ''
)
UI_HTML = UI_HTML.replace(
    "$('agentOut').textContent=JSON.stringify(await r.json(),null,2)}",
    "$('agentOut').textContent=JSON.stringify(await r.json(),null,2);await loadAgents()}"
)
UI_HTML = UI_HTML.replace(
    "showSection(location.hash==='#clients'?'clientsSection':location.hash==='#queries'?'queriesSection':location.hash==='#audit'?'auditSection':'graylogSection');loadServers();",
    "showSection(location.hash==='#clients'?'clientsSection':location.hash==='#queries'?'queriesSection':location.hash==='#audit'?'auditSection':'graylogSection');loadServers().then(loadAgents);"
)
UI_HTML = UI_HTML.replace('</style>', '.section-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}.audit-summary{color:#64748b;font-size:.9rem;padding-top:.35rem}.audit-actions,.audit-pagination{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}.audit-page-size{display:flex;align-items:center;gap:.5rem;margin:0}.audit-page-size select{width:auto}.audit-table-wrap{overflow:auto;margin-top:1rem;border:1px solid #d9e0e7;border-radius:7px}.audit-table{width:100%;min-width:950px;border-collapse:collapse;font-size:.9rem}.audit-table th,.audit-table td{padding:.65rem .7rem;text-align:left;vertical-align:top;border-bottom:1px solid #d9e0e7}.audit-table th{background:#edf2f7;white-space:nowrap}.audit-table tr:last-child td{border-bottom:0}.audit-table .success{color:#15803d;font-weight:600}.audit-table .failed{color:#b91c1c;font-weight:600}.audit-detail{min-width:360px}.audit-detail summary{cursor:pointer;color:#2563eb}.audit-detail pre{min-height:0;margin:.5rem 0 0;font-size:.8rem;max-height:260px}.audit-empty{text-align:center;padding:2rem}.audit-pagination{margin-top:1rem}.audit-pagination button:disabled{opacity:.45;cursor:not-allowed}body.dark .audit-summary{color:#9db4cc}body.dark .audit-table-wrap{border-color:#1e456d}body.dark .audit-table th{background:#102b48}body.dark .audit-table td{border-color:#1e456d}@media(max-width:700px){.section-heading{display:block}.audit-summary{display:block;margin-bottom:.5rem}} </style>', 1)

UI_HTML = UI_HTML.replace('</style>', '.table-row{cursor:pointer}.table-row:hover{background:#f8fafc}.row-actions{white-space:nowrap;text-align:right!important}.row-actions button{margin:.0rem 0 0 .35rem;padding:.4rem .65rem}.badge{display:inline-block;padding:.2rem .5rem;border-radius:999px;background:#e2e8f0;font-size:.8rem}.badge.active{background:#dcfce7;color:#166534}.badge.inactive{background:#fee2e2;color:#991b1b}.modal-backdrop{position:fixed;inset:0;z-index:2000;display:grid;place-items:center;padding:1rem;background:#0f172acc}.modal-backdrop[hidden]{display:none}.modal-card{width:min(720px,100%);max-height:calc(100vh - 2rem);overflow:auto;background:#fff;color:#17202a;border-radius:10px;box-shadow:0 20px 60px #0006;padding:1.25rem}.modal-header{display:flex;align-items:center;justify-content:space-between;gap:1rem}.modal-header h2{margin:0}.modal-close{background:transparent;color:#64748b;font-size:1.5rem;line-height:1;padding:.1rem .4rem;margin:0}.modal-actions{display:flex;justify-content:flex-end;gap:.5rem;flex-wrap:wrap}.modal-actions button{margin-top:1rem}.modal-card textarea{min-height:80px}.modal-card .grid{gap:.8rem}body.dark .table-row:hover{background:#102b48}body.dark .modal-card{background:#0d2138;color:#e5eefb}body.dark .modal-close{color:#c5d8ed}@media(max-width:700px){.modal-card{padding:.9rem}} </style>', 1)

# The original inline form is replaced below; prevent its bootstrap calls from
# touching the removed form controls before the redesigned UI is initialized.
UI_HTML = UI_HTML.replace("loadSaved();", "")
UI_HTML = UI_HTML.replace(";loadServers();", ";")
UI_HTML = UI_HTML.replace(";loadServers().then(loadAgents);", ";")
UI_HTML = UI_HTML.replace("$('kind').onchange=()=>{let s=$('kind').value==='saved';$('saved').hidden=!s;$('savedLabel').hidden=!s};", "")
UI_HTML = UI_HTML.replace("$('kind').onchange=()=>{let s=$('kind').value==='saved';$('saved').hidden=!s;$('savedLabel').hidden=!s};loadSaved();", "$('kind').onchange=()=>{};")
UI_HTML = UI_HTML.replace("showSection(location.hash==='#clients'?'clientsSection':location.hash==='#queries'?'queriesSection':location.hash==='#audit'?'auditSection':'graylogSection');loadServers().then(loadAgents);", "showSection(location.hash==='#clients'?'clientsSection':location.hash==='#queries'?'queriesSection':location.hash==='#audit'?'auditSection':'graylogSection');")

MANAGEMENT_JS = r'''let modalKind='',modalItem=null;
function uiEscape(v){return String(v??'—').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;')}
function modalField(label,id,value='',type='text',placeholder=''){return `<div><label for="${id}">${label}</label><input id="${id}" type="${type}" value="${uiEscape(value)}" placeholder="${uiEscape(placeholder)}"></div>`}
function modalTextarea(label,id,value=''){return `<label for="${id}">${label}</label><textarea id="${id}">${uiEscape(value)}</textarea>`}
function openModal(kind,title,fields,item=null){modalKind=kind;modalItem=item;$('modalTitle').textContent=title;$('modalFields').innerHTML=fields;$('modalStatus').textContent='';$('testModalButton').hidden=kind!=='server';$('editModal').hidden=false;document.body.style.overflow='hidden';setTimeout(()=>document.querySelector('#editModal input, #editModal textarea, #editModal select')?.focus(),0)}
function closeModal(){$('editModal').hidden=true;document.body.style.overflow=''}
function selectOptions(items,selected){return items.map(x=>`<option value="${x.id}" ${String(x.id)===String(selected)?'selected':''}>${uiEscape(x.name)}${x.url?` — ${uiEscape(x.url)}`:''}</option>`).join('')}
function openServerModal(item=null){let s=item||{};openModal('server',item?'Edit Graylog server':'Add Graylog server',`<div class="grid">${modalField('Name','mServerName',s.name,'text','production')}${modalField('URL','mServerUrl',s.url,'url','https://graylog.example.com')}${modalField('API token','mServerToken','','password',item?'Leave blank to keep the current token':'Graylog API token')}${modalField('Timeout (seconds)','mServerTimeout',s.timeout_seconds||30,'number')}<div><label for="mServerTls">Verify TLS</label><select id="mServerTls"><option value="true" ${s.verify_tls!==false?'selected':''}>Yes</option><option value="false" ${s.verify_tls===false?'selected':''}>No</option></select></div></div>` ,item)}
function openAgentModal(item=null){let a=item||{};openModal('agent',item?'Edit MCP client':'Add MCP client',`<div class="grid">${modalField('Client name','mAgentName',a.name,'text','monitoring-agent')}<div><label for="mAgentServer">Assigned Graylog server</label><select id="mAgentServer">${selectOptions(serverItems,a.graylog_server_id)}</select></div>${modalField('API key','mAgentKey','','password',item?'Leave blank to keep the current key':'Leave blank to generate')}${item?'<div><label for="mAgentActive">Status</label><select id="mAgentActive"><option value="true" '+(a.active?'selected':'')+'>Active</option><option value="false" '+(!a.active?'selected':'')+'>Inactive</option></select></div>':''}</div>`,item)}
function openRuleModal(item=null){let q=item||{};openModal('rule',item?'Edit query rule':'Add query rule',`${modalField('Name','mRuleName',q.name,'text','errors_by_service')}${modalField('Description','mRuleDescription',q.description||'','text','Count errors grouped by service')}<div class="grid"><div><label for="mRuleType">Type</label><select id="mRuleType"><option value="messages" ${q.type!=='aggregate'?'selected':''}>Message search</option><option value="aggregate" ${q.type==='aggregate'?'selected':''}>Aggregation</option></select></div>${modalField('Time range (minutes)','mRuleMinutes',q.minutes||60,'number')}${modalField('Message limit','mRuleLimit',q.limit||100,'number')}${modalField('Time bucket','mRuleInterval',q.interval||'','text','5m')}</div>${modalTextarea('Lucene query template','mRuleQuery',q.query||'')}${modalTextarea('Group by JSON','mRuleGroup',JSON.stringify(q.group_by||[],null,2))}${modalTextarea('Metrics JSON','mRuleMetrics',JSON.stringify(q.metrics||[{function:'count'}],null,2))}${modalTextarea('Default parameters JSON','mRuleDefaults',JSON.stringify(q.defaults||{},null,2))}${modalTextarea('Instructions for the agent','mRuleInstructions',q.instructions||'')}`,item)}
function renderServers(){if(!serverItems.length){$('serversOut').innerHTML='<p class="audit-empty muted">No Graylog servers configured.</p>';return}$('serversOut').innerHTML='<table class="audit-table"><thead><tr><th>Name</th><th>URL</th><th>TLS</th><th>Timeout</th><th>Created</th><th>Actions</th></tr></thead><tbody>'+serverItems.map(s=>`<tr class="table-row" ondblclick="openServerModal(serverItems.find(x=>x.id===${s.id}))"><td><strong>${uiEscape(s.name)}</strong></td><td>${uiEscape(s.url)}</td><td>${s.verify_tls?'Enabled':'Disabled'}</td><td>${uiEscape(s.timeout_seconds)} s</td><td>${uiEscape(s.created_at)}</td><td class="row-actions"><button class="secondary" onclick="event.stopPropagation();openServerModal(serverItems.find(x=>x.id===${s.id}))">Edit</button><button class="secondary" onclick="event.stopPropagation();deleteServerItem(${s.id})">Delete</button></td></tr>`).join('')+'</tbody></table>'}
async function loadServers(){let r=await fetch('/ui/api/servers'),d=await r.json();serverItems=d.items||[];renderServers();if(typeof loadAgents==='function')await loadAgents()}
function renderAgents(){if(!agentItems.length){$('agentsOut').innerHTML='<p class="audit-empty muted">No MCP clients configured.</p>';return}$('agentsOut').innerHTML='<table class="audit-table"><thead><tr><th>Name</th><th>Graylog server</th><th>API key</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>'+agentItems.map(a=>`<tr class="table-row" ondblclick="openAgentModal(agentItems.find(x=>x.id===${a.id}))"><td><strong>${uiEscape(a.name)}</strong></td><td>${uiEscape(a.graylog_server_name)}</td><td>••••${uiEscape(a.api_key_last4)}</td><td><span class="badge ${a.active?'active':'inactive'}">${a.active?'Active':'Inactive'}</span></td><td>${uiEscape(a.created_at)}</td><td class="row-actions"><button class="secondary" onclick="event.stopPropagation();openAgentModal(agentItems.find(x=>x.id===${a.id}))">Edit</button><button class="secondary" onclick="event.stopPropagation();deleteAgentItem(${a.id})">Delete</button></td></tr>`).join('')+'</tbody></table>'}
let agentItems=[];async function loadAgents(){let r=await fetch('/ui/api/agents'),d=await r.json();agentItems=d.items||[];renderAgents()}
function renderQueries(){if(!queryItems.length){$('queriesOut').innerHTML='<p class="audit-empty muted">No query rules configured.</p>';return}$('queriesOut').innerHTML='<table class="audit-table"><thead><tr><th>Name</th><th>Description</th><th>Type</th><th>Time range</th><th>Limit</th><th>Actions</th></tr></thead><tbody>'+queryItems.map((q,i)=>`<tr class="table-row" ondblclick="openRuleModal(queryItems[${i}])"><td><strong>${uiEscape(q.name)}</strong></td><td>${uiEscape(q.description||'—')}</td><td>${q.type==='aggregate'?'Aggregation':'Messages'}</td><td>${uiEscape(q.minutes||60)} min</td><td>${uiEscape(q.limit||100)}</td><td class="row-actions"><button class="secondary" onclick="event.stopPropagation();openRuleModal(queryItems[${i}])">Edit</button><button class="secondary" onclick="event.stopPropagation();deleteRuleItem(queryItems[${i}].name)">Delete</button></td></tr>`).join('')+'</tbody></table>'}
async function loadSaved(){let r=await fetch('/ui/api/queries'),d=await r.json();queryItems=d.queries||[];if($('saved'))$('saved').innerHTML=queryItems.map(x=>`<option value="${uiEscape(x.name)}">${uiEscape(x.name)} — ${uiEscape(x.description||'')}</option>`).join('');renderQueries()}
function serverModalPayload(){return {name:$('mServerName').value.trim(),url:$('mServerUrl').value.trim(),api_token:$('mServerToken').value,verify_tls:$('mServerTls').value==='true',timeout_seconds:+$('mServerTimeout').value||30}}
async function testModalServer(){let b=serverModalPayload();if(modalItem)b.server_id=modalItem.id;$('modalStatus').textContent='Testing connection…';let r=await fetch('/ui/api/servers/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}),d=await r.json();$('modalStatus').textContent=(d.success?'✓ ':'✗ ')+(d.message||d.detail||'Connection test failed.');$('modalStatus').style.color=d.success?'#15803d':'#b91c1c'}
async function submitModal(e){e.preventDefault();let r,d;try{let creatingAgent=modalKind==='agent'&&!modalItem;if(modalKind==='server'){let b=serverModalPayload();r=await fetch('/ui/api/servers',{method:modalItem?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(modalItem?{...b,server_id:modalItem.id}:b)})}else if(modalKind==='agent'){let b={name:$('mAgentName').value.trim(),graylog_server_id:+$('mAgentServer').value};if($('mAgentKey').value)b.api_key=$('mAgentKey').value;if(modalItem){b={...b,agent_id:modalItem.id,active:$('mAgentActive').value==='true'};r=await fetch('/ui/api/agents',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})}else r=await fetch('/ui/api/agents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})}else{let b={name:$('mRuleName').value.trim(),description:$('mRuleDescription').value,type:$('mRuleType').value,query:$('mRuleQuery').value,minutes:+$('mRuleMinutes').value,limit:+$('mRuleLimit').value,interval:$('mRuleInterval').value,group_by:JSON.parse($('mRuleGroup').value),metrics:JSON.parse($('mRuleMetrics').value),defaults:JSON.parse($('mRuleDefaults').value),instructions:$('mRuleInstructions').value};r=await fetch('/ui/api/queries',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})}d=await r.json();if(!r.ok)throw new Error(d.detail||'Save failed.');if(modalKind==='server')await loadServers();else if(modalKind==='agent')await loadAgents();else await loadSaved();if(creatingAgent&&d.api_key){$('modalStatus').innerHTML='<span class="success">✓ Client created. Copy this API key now; it will not be shown again.</span><label for="generatedApiKey">Generated API key</label><input id="generatedApiKey" value="'+uiEscape(d.api_key)+'" readonly onclick="this.select()">';$('modalStatus').style.color='#15803d';return false}closeModal()}catch(err){$('modalStatus').textContent='✗ '+err.message;$('modalStatus').style.color='#b91c1c'}return false}
async function deleteServerItem(id){let s=serverItems.find(x=>x.id===id);if(!s||!confirm(`Delete Graylog server “${s.name}”?`))return;let r=await fetch('/ui/api/servers?id='+id,{method:'DELETE'}),d=await r.json();if(!r.ok)alert(d.detail||'Delete failed.');await loadServers()}
async function deleteAgentItem(id){let a=agentItems.find(x=>x.id===id);if(!a||!confirm(`Delete MCP client “${a.name}”?`))return;let r=await fetch('/ui/api/agents?id='+id,{method:'DELETE'}),d=await r.json();if(!r.ok)alert(d.detail||'Delete failed.');await loadAgents()}
async function deleteRuleItem(name){if(!confirm(`Delete query rule “${name}”?`))return;let r=await fetch('/ui/api/queries?name='+encodeURIComponent(name),{method:'DELETE'});if(!r.ok)alert('Delete failed.');await loadSaved()}
function showSection(id){document.querySelectorAll('.page-section').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.nav-links a').forEach(x=>x.classList.toggle('active',x.dataset.section===id));$('navLinks').classList.remove('open');if(id==='auditSection')loadAudit();if(id==='graylogSection')loadServers();if(id==='clientsSection')loadAgents();if(id==='queriesSection')loadSaved()}
loadServers();loadSaved();'''
UI_HTML = UI_HTML.replace('</script></body></html>', MANAGEMENT_JS + '</script></body></html>')
UI_HTML = UI_HTML.replace('<a class="help-link"', '<a class="logout-link" href="/logout">Logout</a><a class="help-link"')
UI_HTML = UI_HTML.replace('</style>', '.logout-link{color:#dbeafe;text-decoration:none;padding:.45rem .55rem;border-radius:5px}.logout-link:hover{background:#244f78} </style>', 1)

def _ui_authorized(request: Request) -> bool:
    token = request.cookies.get(UI_SESSION_COOKIE)
    expires_at = ui_sessions.get(token or "")
    if not expires_at: return False
    if expires_at <= time.time():
        ui_sessions.pop(token, None)
        return False
    return True

def _ui_unauthorized():
    return PlainTextResponse("Authentication required", status_code=401)

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in — Graylog MCP</title><style>body{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7fa;color:#17202a}.login-card{width:min(380px,calc(100% - 2rem));background:#fff;border:1px solid #d9e0e7;border-radius:10px;padding:2rem;box-shadow:0 8px 24px #0002}h1{margin:0 0 .35rem;color:#102a43;font-size:1.5rem}p{color:#64748b;margin:.25rem 0 1.5rem}label{display:block;font-weight:600;margin:.9rem 0 .25rem}input,button{font:inherit;box-sizing:border-box;width:100%;padding:.65rem;border:1px solid #b8c3ce;border-radius:5px}button{margin-top:1.25rem;background:#2563eb;color:#fff;border:0;cursor:pointer}.error{color:#b91c1c;background:#fef2f2;border-radius:5px;padding:.65rem;margin-bottom:1rem}@media(prefers-color-scheme:dark){body{background:#071426;color:#e5eefb}.login-card{background:#0d2138;border-color:#1e456d}h1{color:#e5eefb}p{color:#9db4cc}input{background:#102b48;color:#e5eefb;border-color:#32618e}.error{background:#451a1a;color:#fecaca}}</style></head><body><main class="login-card"><h1>Graylog MCP</h1><p>Sign in to the WebUI</p>{error}<form method="post" action="/login"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form></main></body></html>"""

def _login_page(error: str = "") -> HTMLResponse:
    message = f'<div class="error">{error}</div>' if error else ""
    return HTMLResponse(LOGIN_HTML.replace("{error}", message))

@mcp.custom_route("/login", methods=["GET", "POST"])
async def ui_login(request: Request):
    if request.method == "GET":
        return RedirectResponse("/", status_code=303) if _ui_authorized(request) else _login_page()
    body = (await request.body()).decode("utf-8", errors="replace")
    from urllib.parse import parse_qs
    form = parse_qs(body)
    username = form.get("username", [""])[0]
    password = form.get("password", [""])[0]
    if not (hmac.compare_digest(username, settings.ui_username) and hmac.compare_digest(password, settings.ui_password)):
        return _login_page("Invalid username or password.")
    token = secrets.token_urlsafe(32)
    ui_sessions[token] = time.time() + UI_SESSION_TTL
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(UI_SESSION_COOKIE, token, max_age=UI_SESSION_TTL, httponly=True, samesite="lax", path="/")
    return response

@mcp.custom_route("/logout", methods=["GET", "POST"])
async def ui_logout(request: Request):
    token = request.cookies.get(UI_SESSION_COOKIE)
    if token: ui_sessions.pop(token, None)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(UI_SESSION_COOKIE, path="/")
    return response

@mcp.custom_route("/", methods=["GET"])
async def ui_home(request: Request):
    return RedirectResponse("/login", status_code=303) if not _ui_authorized(request) else HTMLResponse(UI_HTML)

@mcp.custom_route("/ui/help", methods=["GET"])
async def ui_help(request: Request):
    return RedirectResponse("/login", status_code=303) if not _ui_authorized(request) else HTMLResponse(DOCS_HTML)

@mcp.custom_route("/ui/api/queries", methods=["GET", "POST", "DELETE"])
async def ui_queries(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    if request.method == "POST":
        try:
            data = await request.json(); name = data.pop("name").strip()
            if not name or not data.get("query"): raise ValueError("Name and query are required")
            return JSONResponse(await audit.save_query(name, data))
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    if request.method == "DELETE":
        await audit.remove_query(request.query_params["name"]); return JSONResponse({"deleted": True})
    return JSONResponse({"queries": await audit.list_queries()})

@mcp.custom_route("/ui/api/query", methods=["POST"])
async def ui_query(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = await request.json(); selected_client = await get_client(data.get("server_id"))
    kind = "aggregate" if data.get("group_by") is not None else "search"
    result = await selected_client.aggregate(data["query"], data.get("minutes", 60), data.get("group_by"), data.get("metrics")) if kind == "aggregate" else await selected_client.search_messages(data["query"], data.get("minutes", 15), data.get("limit", settings.graylog_default_limit))
    return JSONResponse(result)

@mcp.custom_route("/ui/api/saved", methods=["POST"])
async def ui_saved(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = await request.json(); q = await render_saved_query(data["name"], data.get("parameters", {})); kind = q.get("type", "messages"); selected_client = await get_client(data.get("server_id"))
    result = await selected_client.aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval")) if kind == "aggregate" else await selected_client.search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
    return JSONResponse(result)

@mcp.custom_route("/ui/api/streams", methods=["GET"])
async def ui_streams(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = request.query_params.get("server_id")
    return JSONResponse(await (await get_client(int(data) if data else None)).streams())

@mcp.custom_route("/ui/api/servers", methods=["GET", "POST", "PUT", "DELETE"])
async def ui_servers(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    if request.method == "POST":
        try: return JSONResponse(await audit.add_server(**(await request.json())), status_code=201)
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    if request.method == "PUT":
        try:
            data = await request.json(); server_id = int(data.pop("server_id"))
            updated = await audit.update_server(server_id, **data)
            stale_client = clients.pop(server_id, None)
            if stale_client: await stale_client.close()
            return JSONResponse(updated)
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    if request.method == "DELETE":
        try:
            server_id = int(request.query_params["id"])
            await audit.remove_server(server_id)
            stale_client = clients.pop(server_id, None)
            if stale_client: await stale_client.close()
            return JSONResponse({"deleted": True})
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse({"items": await audit.list_servers()})

def _safe_url(value: str) -> str:
    """Return a display-safe URL without exposing embedded credentials."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))
    except ValueError:
        return value

def _connection_error_message(exc: Exception, url: str) -> str:
    endpoint = _safe_url(url)
    if isinstance(exc, GraylogError):
        return f"Graylog API returned an error.\nDetails: {exc}"
    if isinstance(exc, httpx.ConnectTimeout):
        return f"Connection to {endpoint} timed out.\nCheck that the server is reachable and increase Timeout (seconds) if needed."
    if isinstance(exc, httpx.ConnectError):
        detail = str(exc.__cause__ or exc).strip()
        if detail == "All connection attempts failed":
            detail = "No TCP connection could be established; the host or port did not respond."
        return f"Could not connect to {endpoint}.\nDetails: {detail}\nCheck the URL, DNS, port, and firewall."
    if isinstance(exc, httpx.TimeoutException):
        return f"The request to {endpoint} timed out.\nCheck that Graylog is reachable and increase Timeout (seconds) if needed."
    return f"Connection test failed for {endpoint}.\nError type: {type(exc).__name__}\nDetails: {exc}"

@mcp.custom_route("/ui/api/servers/test", methods=["POST"])
async def ui_test_server(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = await request.json(); temporary = None
    try:
        stored = await audit.get_server(int(data["server_id"])) if data.get("server_id") else None
        server = dict(stored or {})
        for field in ("url", "api_token", "verify_tls", "timeout_seconds"):
            if data.get(field) not in (None, ""): server[field] = data[field]
        if not server or not server.get("url") or not server.get("api_token"):
            return JSONResponse({"success": False, "message": "Enter a URL and Graylog API token."}, status_code=400)
        temporary = GraylogClient(settings, audit, server=server)
        result = await temporary.request("GET", "/api/cluster")
        return JSONResponse({"success": True, "message": "The Graylog API connection is working.", "cluster": result})
    except Exception as exc:
        return JSONResponse({"success": False, "message": _connection_error_message(exc, server.get("url", data.get("url", "")))}, status_code=502)
    finally:
        if temporary: await temporary.close()

@mcp.custom_route("/ui/api/agents", methods=["GET", "POST", "PUT", "DELETE"])
async def ui_agents(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    if request.method == "POST":
        try:
            data = await request.json(); data["server_id"] = data.pop("graylog_server_id")
            return JSONResponse(await audit.add_agent(**data), status_code=201)
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    if request.method == "PUT":
        try:
            data = await request.json(); agent_id = int(data.pop("agent_id")); data["server_id"] = data.pop("graylog_server_id")
            return JSONResponse(await audit.update_agent(agent_id, **data))
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    if request.method == "DELETE":
        await audit.remove_agent(int(request.query_params["id"])); return JSONResponse({"deleted": True})
    return JSONResponse({"items": await audit.list_agents()})

async def execute(name: str, args: dict[str, Any]):
    selected_client = await get_client()
    if name == "search_messages": return await selected_client.search_messages(**args)
    if name == "aggregate": return await selected_client.aggregate(**args)
    if name == "list_saved_queries": return {"queries": await query_summaries()}
    if name == "run_saved_query":
        q = await render_saved_query(args["name"], args.get("parameters", {}))
        if q.get("type", "messages") == "aggregate":
            return await selected_client.aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval"))
        return await selected_client.search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
    raise ValueError(f"Unsupported tool: {name}")

@mcp.tool()
async def search_messages(query: str, minutes: int = 15, limit: int | None = None, fields: list[str] | None = None) -> str:
    """Search Graylog messages with a Lucene query over a relative time window."""
    return json.dumps(await (await get_client()).search_messages(query, minutes, limit or settings.graylog_default_limit, fields), ensure_ascii=False)

@mcp.tool()
async def aggregate(query: str, minutes: int = 60, group_by: list[dict] | None = None, metrics: list[dict] | None = None, interval: str = "5m") -> str:
    """Run a Graylog aggregation. Metrics follow Graylog's aggregate API format."""
    return json.dumps(await (await get_client()).aggregate(query, minutes, group_by, metrics, interval), ensure_ascii=False)

@mcp.tool()
async def list_streams() -> str:
    """List Graylog streams."""
    return json.dumps(await (await get_client()).streams(), ensure_ascii=False)

@mcp.tool()
async def list_saved_queries() -> str:
    """List database-managed query templates and their agent instructions."""
    return json.dumps({"queries": await query_summaries()}, ensure_ascii=False)

@mcp.tool()
async def run_saved_query(name: str, parameters: dict[str, Any] | None = None) -> str:
    """Run a database-managed query template with parameter overrides."""
    q = await render_saved_query(name, parameters or {})
    kind = q.get("type", "messages")
    if kind == "aggregate": result = await (await get_client()).aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval", "5m"))
    else: result = await (await get_client()).search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
    return json.dumps(result, ensure_ascii=False)

@mcp.tool()
async def ask_graylog(question: str) -> str:
    """Answer a Graylog question using OpenAI to orchestrate Graylog tools."""
    if not settings.openai_api_key: return "OpenAI is not configured. Use search_messages, aggregate or run_saved_query directly."
    return await OpenAIAgent(settings, TOOL_SCHEMAS, audit).ask(question, execute)

@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request):
    return JSONResponse({"status": "ok", "service": "custom-graylog-mcp"})

@mcp.custom_route("/ui/api/audit", methods=["GET"])
async def ui_audit(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    try: limit = int(request.query_params.get("limit", "100"))
    except ValueError: limit = 100
    return JSONResponse({"items": await audit.recent(limit, request.query_params.get("q"), request.query_params.get("source"))})

# Mount after all MCP tools and custom routes have been registered.
api.mount("/", mcp.streamable_http_app())

def main():
    import uvicorn
    uvicorn.run(api, host=settings.mcp_host, port=settings.mcp_port, log_level=settings.log_level.lower())

if __name__ == "__main__": main()
