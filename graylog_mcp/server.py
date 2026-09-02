from __future__ import annotations

import json
import logging
import base64
import hmac
import string
from contextvars import ContextVar
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .catalog import QueryCatalog
from .config import Settings
from .graylog import GraylogClient
from .openai_agent import OpenAIAgent
from .audit import AuditStore

settings = Settings()
logging.basicConfig(level=settings.log_level)
audit = AuditStore(settings.audit_db_path, settings.audit_retention_days, settings.audit_max_rows, settings.audit_max_payload_chars)
clients: dict[int, GraylogClient] = {}
agent_context: ContextVar[dict | None] = ContextVar("agent_context", default=None)
bearer = HTTPBearer(auto_error=False)
catalog = QueryCatalog(settings.query_catalog_path)

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
async def api_audit(q: str | None = Query(None, description="FTS5 fulltext expression"), source: str | None = None, limit: int = Query(100, ge=1, le=500), _agent=Depends(require_agent)):
    return {"items": await audit.recent(limit, q, source)}

UI_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graylog MCP</title><style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fa;color:#17202a;transition:background .2s,color .2s}
header{position:sticky;top:0;z-index:1000;background:#102a43;color:#fff;box-shadow:0 2px 8px #0004}.nav-wrap{max-width:1100px;margin:auto;display:flex;align-items:center;justify-content:space-between;padding:.7rem 1rem}.brand{font-weight:700}.nav-toggle{display:none;background:#244f78;color:#fff;margin:0}.nav-links{display:flex;gap:.4rem}.nav-links a{color:#dbeafe;text-decoration:none;padding:.5rem .7rem;border-radius:5px}.nav-links a.active,.nav-links a:hover{background:#2563eb;color:#fff}
main{max-width:1100px;margin:2rem auto;padding:0 1rem}.page-section{display:none;background:white;border:1px solid #d9e0e7;border-radius:10px;padding:1.25rem;box-shadow:0 2px 8px #0001;transition:background .2s,border-color .2s}.page-section.active{display:block}
label{display:block;font-weight:600;margin:.8rem 0 .25rem}input,select,textarea,button{font:inherit;padding:.55rem;border:1px solid #b8c3ce;border-radius:5px;box-sizing:border-box;width:100%}
textarea{min-height:90px;font-family:ui-monospace,monospace}button{width:auto;background:#2563eb;color:white;border:0;cursor:pointer;margin-top:1rem}button.secondary{background:#566573}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:700px){.grid{grid-template-columns:1fr}}
pre{background:#111827;color:#d1fae5;padding:1rem;border-radius:6px;overflow:auto;min-height:180px}.muted{color:#64748b}.theme{background:#e2e8f0;color:#17202a;margin:0}.nav-links{margin-left:auto}.nav-wrap{gap:.5rem}
body.dark{background:#071426;color:#e5eefb}body.dark .page-section{background:#0d2138;border-color:#1e456d}body.dark input,body.dark select,body.dark textarea{background:#102b48;color:#e5eefb;border-color:#32618e}body.dark .muted{color:#9db4cc}body.dark .theme{background:#21476e;color:#e5eefb}
@media(max-width:700px){main{margin:1rem auto;padding:0 .7rem}.nav-toggle{display:block}.nav-links{display:none;position:absolute;top:3.3rem;left:0;right:0;background:#102a43;flex-direction:column;padding:.5rem 1rem;box-shadow:0 4px 8px #0003}.nav-links.open{display:flex}.nav-wrap{position:relative}.page-section{padding:.9rem}.grid{grid-template-columns:1fr}h1{font-size:1.45rem}h2{font-size:1.2rem}}
</style></head><body><header><div class="nav-wrap"><div class="brand">Graylog MCP</div><button class="nav-toggle" onclick="toggleMenu()" aria-label="Open menu">☰ Menu</button><nav class="nav-links" id="navLinks"><a href="#graylog" data-section="graylogSection">Graylog Servers</a><a href="#clients" data-section="clientsSection">MCP Clients</a><a href="#queries" data-section="queriesSection">Query Rules</a><a href="#audit" data-section="auditSection">Audit Log</a></nav><button class="theme" onclick="toggleTheme()" id="themeButton">Dark mode</button></div></header><main>
<section id="graylogSection" class="page-section active"><h2>Graylog Servers</h2><div class="grid"><div><label>Name</label><input id="serverName" placeholder="production"></div><div><label>URL</label><input id="serverUrl" placeholder="https://graylog.example.com"></div><div><label>API token</label><input id="serverToken" type="password" placeholder="leave blank when editing to keep the current token"></div><div><label>Verify TLS</label><select id="serverTls"><option value="true">yes</option><option value="false">no</option></select></div><div><label>Timeout (seconds)</label><input id="serverTimeout" type="number" value="30" min="1"></div></div><button onclick="testServer()" class="secondary">Test connection</button> <button onclick="addServer()">Add server</button> <button onclick="updateServer()">Save changes</button> <label>Existing server</label><select id="serverId" onchange="selectServer()"></select> <button class="secondary" onclick="loadServers()">Refresh servers</button><p id="serverStatus" class="muted"></p>
<label>Query type</label><select id="kind"><option value="search">Message search</option><option value="aggregate">Aggregation</option><option value="saved">Managed query</option></select>
<label id="savedLabel" hidden>Managed query</label><select id="saved" hidden></select>
<label>Graylog query (Lucene)</label><textarea id="query" placeholder="level:3 OR service:api"></textarea>
<div class="grid"><div><label>Time range (minutes)</label><input id="minutes" type="number" value="60" min="1"></div><div><label>Message limit</label><input id="limit" type="number" value="100" min="1"></div></div>
<label>Group by (aggregation only, comma-separated)</label><input id="groupBy" placeholder="service,source">
<label>Metrics JSON (aggregation only)</label><input id="metrics" value='[{"function":"count"}]'>
<button onclick="run()">Run query</button> <button class="secondary" onclick="loadStreams()">Load streams</button>
<h2>Result</h2><pre id="out">Ready.</pre></section>
<section id="clientsSection" class="page-section"><h2>MCP Clients / Agents</h2><p class="muted">Each client is restricted to one Graylog server. The API key is displayed only when the client is created.</p><div class="grid"><div><label>Client name</label><input id="agentName" placeholder="monitoring-agent"></div><div><label>API key (optional)</label><input id="agentKey" type="password" placeholder="leave blank to generate"></div></div><button onclick="addAgent()">Add client</button><pre id="agentOut">A newly generated API key will be shown here once.</pre></section>
<section id="queriesSection" class="page-section"><h2>MCP Query Rules</h2><p class="muted">Define reusable filters and aggregation behavior available to MCP agents.</p><label>Existing rule</label><select id="ruleId" onchange="selectRule()"></select><div class="grid"><div><label>Name</label><input id="ruleName" placeholder="errors_by_service"></div><div><label>Description</label><input id="ruleDescription" placeholder="Count errors grouped by service"></div><div><label>Type</label><select id="ruleType"><option value="messages">Message search</option><option value="aggregate">Aggregation</option></select></div><div><label>Time range (minutes)</label><input id="ruleMinutes" type="number" value="60" min="1"></div><div><label>Message limit</label><input id="ruleLimit" type="number" value="100" min="1"></div><div><label>Time bucket</label><input id="ruleInterval" placeholder="5m"></div></div><label>Lucene query template</label><textarea id="ruleQuery" placeholder="service:${service} AND level:3"></textarea><label>Group by JSON</label><textarea id="ruleGroup">[]</textarea><label>Metrics JSON</label><textarea id="ruleMetrics">[{"function":"count"}]</textarea><label>Default parameters JSON</label><textarea id="ruleDefaults">{}</textarea><label>Instructions for the agent</label><textarea id="ruleInstructions" placeholder="Use this rule when the user asks for error counts by service."></textarea><button onclick="saveRule()">Save rule</button> <button class="secondary" onclick="newRule()">New rule</button> <button class="secondary" onclick="deleteRule()">Delete rule</button><p id="ruleStatus" class="muted"></p></section>
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

def _ui_authorized(request: Request) -> bool:
    value = request.headers.get("authorization", "")
    if not value.lower().startswith("basic "): return False
    try: raw = base64.b64decode(value.split(" ", 1)[1]).decode()
    except (ValueError, UnicodeDecodeError): return False
    username, _, password = raw.partition(":")
    return hmac.compare_digest(username, settings.ui_username) and hmac.compare_digest(password, settings.ui_password)

def _ui_unauthorized():
    return PlainTextResponse("Authentication required", status_code=401, headers={"WWW-Authenticate": 'Basic realm="Graylog MCP UI"'})

@mcp.custom_route("/", methods=["GET"])
async def ui_home(request: Request):
    return _ui_unauthorized() if not _ui_authorized(request) else HTMLResponse(UI_HTML)

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

@mcp.custom_route("/ui/api/servers", methods=["GET", "POST", "PUT"])
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
    return JSONResponse({"items": await audit.list_servers()})

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
        return JSONResponse({"success": False, "message": str(exc)}, status_code=502)
    finally:
        if temporary: await temporary.close()

@mcp.custom_route("/ui/api/agents", methods=["GET", "POST", "DELETE"])
async def ui_agents(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    if request.method == "POST":
        try:
            data = await request.json(); data["server_id"] = data.pop("graylog_server_id")
            return JSONResponse(await audit.add_agent(**data), status_code=201)
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
