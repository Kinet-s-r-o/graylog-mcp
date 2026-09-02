from __future__ import annotations

import json
import logging
import base64
import hmac
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
    yield
    await audit.close()
    for graylog_client in clients.values(): await graylog_client.close()
    clients.clear()

api = FastAPI(title="Custom Graylog MCP API", version="0.1.0",
              description="REST API for Graylog searches, aggregations and saved queries.", lifespan=api_lifespan)

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
    return {"queries": [{"name": n, "description": catalog.get(n).get("description", "")} for n in catalog.names()]}

@api.post("/api/v1/queries/run", tags=["Saved queries"])
async def api_run_query(body: SavedQueryRequest, _agent=Depends(require_agent)):
    try: q = catalog.render(body.name, body.parameters)
    except KeyError as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc
    if q.get("type", "messages") == "aggregate":
        return await (await get_client()).aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval"))
    return await (await get_client()).search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))

@api.get("/api/v1/audit", tags=["Audit"])
async def api_audit(q: str | None = Query(None, description="FTS5 fulltext expression"), source: str | None = None, limit: int = Query(100, ge=1, le=500), _agent=Depends(require_agent)):
    return {"items": await audit.recent(limit, q, source)}

UI_HTML = """<!doctype html>
<html lang="sk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graylog MCP</title><style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fa;color:#17202a;transition:background .2s,color .2s}
header{background:#102a43;color:#fff;box-shadow:0 2px 8px #0002}.nav-wrap{max-width:1100px;margin:auto;display:flex;align-items:center;justify-content:space-between;padding:.7rem 1rem}.brand{font-weight:700}.nav-toggle{display:none;background:#244f78;color:#fff;margin:0}.nav-links{display:flex;gap:.4rem}.nav-links a{color:#dbeafe;text-decoration:none;padding:.5rem .7rem;border-radius:5px}.nav-links a.active,.nav-links a:hover{background:#2563eb;color:#fff}
main{max-width:1100px;margin:2rem auto;padding:0 1rem}.page-section{display:none;background:white;border:1px solid #d9e0e7;border-radius:10px;padding:1.25rem;box-shadow:0 2px 8px #0001;transition:background .2s,border-color .2s}.page-section.active{display:block}
label{display:block;font-weight:600;margin:.8rem 0 .25rem}input,select,textarea,button{font:inherit;padding:.55rem;border:1px solid #b8c3ce;border-radius:5px;box-sizing:border-box;width:100%}
textarea{min-height:90px;font-family:ui-monospace,monospace}button{width:auto;background:#2563eb;color:white;border:0;cursor:pointer;margin-top:1rem}button.secondary{background:#566573}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:700px){.grid{grid-template-columns:1fr}}
pre{background:#111827;color:#d1fae5;padding:1rem;border-radius:6px;overflow:auto;min-height:180px}.muted{color:#64748b}.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem}.theme{background:#e2e8f0;color:#17202a;margin:0}
body.dark{background:#071426;color:#e5eefb}body.dark .page-section{background:#0d2138;border-color:#1e456d}body.dark input,body.dark select,body.dark textarea{background:#102b48;color:#e5eefb;border-color:#32618e}body.dark .muted{color:#9db4cc}body.dark .theme{background:#21476e;color:#e5eefb}
@media(max-width:700px){main{margin:1rem auto;padding:0 .7rem}.nav-toggle{display:block}.nav-links{display:none;position:absolute;top:3.3rem;left:0;right:0;background:#102a43;flex-direction:column;padding:.5rem 1rem;box-shadow:0 4px 8px #0003}.nav-links.open{display:flex}.nav-wrap{position:relative}.topbar{align-items:flex-start}.page-section{padding:.9rem}.grid{grid-template-columns:1fr}h1{font-size:1.45rem}h2{font-size:1.2rem}}
</style></head><body><header><div class="nav-wrap"><div class="brand">Graylog MCP</div><button class="nav-toggle" onclick="toggleMenu()" aria-label="Otvoriť menu">☰ Menu</button><nav class="nav-links" id="navLinks"><a href="#graylog" data-section="graylogSection">Graylog servery</a><a href="#clients" data-section="clientsSection">MCP klienti</a><a href="#audit" data-section="auditSection">Audit Log</a></nav></div></header><main><div class="topbar"><div><h1>Graylog MCP</h1><p class="muted">Webové rozhranie pre správu serverov, agentov a audit logu.</p></div><button class="theme" onclick="toggleTheme()" id="themeButton">Tmavý režim</button></div>
<section id="graylogSection" class="page-section active"><h2>Graylog servery</h2><div class="grid"><div><label>Názov</label><input id="serverName" placeholder="produkcia"></div><div><label>URL</label><input id="serverUrl" placeholder="https://graylog.example.com"></div><div><label>API token</label><input id="serverToken" type="password"></div><div><label>TLS overenie</label><select id="serverTls"><option value="true">áno</option><option value="false">nie</option></select></div></div><button onclick="testServer()" class="secondary">Otestovať pripojenie</button> <button onclick="addServer()">Pridať Graylog server</button> <select id="serverId"></select> <button class="secondary" onclick="loadServers()">Obnoviť servery</button><p id="serverStatus" class="muted"></p>
<label>Typ dotazu</label><select id="kind"><option value="search">Vyhľadávanie správ</option><option value="aggregate">Agregácia</option><option value="saved">Uložený dotaz</option></select>
<label id="savedLabel" hidden>Uložený dotaz</label><select id="saved" hidden></select>
<label>Graylog dotaz (Lucene)</label><textarea id="query" placeholder="level:3 OR service:api"></textarea>
<div class="grid"><div><label>Časové okno (minúty)</label><input id="minutes" type="number" value="60" min="1"></div><div><label>Limit správ</label><input id="limit" type="number" value="100" min="1"></div></div>
<label>Group by (len pre agregáciu, čiarkami oddelené)</label><input id="groupBy" placeholder="service,source">
<label>Metriky JSON (len pre agregáciu)</label><input id="metrics" value='[{"function":"count"}]'>
<button onclick="run()">Spustiť dotaz</button> <button class="secondary" onclick="loadStreams()">Načítať streamy</button>
<h2>Výsledok</h2><pre id="out">Pripravené.</pre></section>
<section id="clientsSection" class="page-section"><h2>MCP klienti / agenti</h2><p class="muted">Každý klient je viazaný na jeden Graylog server. API kľúč sa zobrazí iba pri vytvorení.</p><div class="grid"><div><label>Názov klienta</label><input id="agentName" placeholder="monitoring-agent"></div><div><label>API kľúč (voliteľné)</label><input id="agentKey" type="password" placeholder="prázdne = vygenerovať"></div></div><button onclick="addAgent()">Pridať klienta</button><pre id="agentOut">Po vytvorení sa nový API kľúč zobrazí iba raz.</pre></section>
<section id="auditSection" class="page-section"><h2>Audit log</h2><div class="grid"><div><label>Fulltext audit logu</label><input id="auditSearch" placeholder="napr. authentication OR timeout"></div><div><label>Zdroj</label><select id="auditSource"><option value="">Všetky</option><option>graylog</option><option>openai</option><option>mcp</option></select></div></div><button class="secondary" onclick="loadAudit()">Vyhľadať v audit logu</button><pre id="auditOut">Audit log sa načíta po vyhľadaní.</pre></section></main><script>
const $=id=>document.getElementById(id); async function loadSaved(){let r=await fetch('/ui/api/queries');let d=await r.json();$('saved').innerHTML=d.queries.map(x=>`<option value="${x.name}">${x.name} — ${x.description}</option>`).join('')}
$('kind').onchange=()=>{let s=$('kind').value==='saved';$('saved').hidden=!s;$('savedLabel').hidden=!s};loadSaved();
async function loadServers(){let r=await fetch('/ui/api/servers');let d=await r.json();$('serverId').innerHTML=d.items.map(x=>`<option value="${x.id}">${x.name} (${x.url})</option>`).join('')}
async function addServer(){let b={name:$('serverName').value,url:$('serverUrl').value,api_token:$('serverToken').value,verify_tls:$('serverTls').value==='true'};let r=await fetch('/ui/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('out').textContent=JSON.stringify(await r.json(),null,2);loadServers()}
async function testServer(){let b={name:$('serverName').value,url:$('serverUrl').value,api_token:$('serverToken').value,verify_tls:$('serverTls').value==='true'};if(!b.url||!b.api_token)b.server_id=+$('serverId').value;$('serverStatus').textContent='Testujem pripojenie...';let r=await fetch('/ui/api/servers/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});let d=await r.json();$('serverStatus').textContent=(d.success?'✓ ':'✗ ')+(d.message||d.detail);$('serverStatus').style.color=d.success?'#15803d':'#b91c1c'}
async function addAgent(){let b={name:$('agentName').value,graylog_server_id:+$('serverId').value};if($('agentKey').value)b.api_key=$('agentKey').value;let r=await fetch('/ui/api/agents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('agentOut').textContent=JSON.stringify(await r.json(),null,2)}
async function run(){let k=$('kind').value,b={server_id:+$('serverId').value};if(k==='saved'){b={...b,name:$('saved').value,parameters:{}}}else if(k==='search'){b={...b,query:$('query').value,minutes:+$('minutes').value,limit:+$('limit').value}}else{try{b={...b,query:$('query').value,minutes:+$('minutes').value,group_by:$('groupBy').value.split(',').map(x=>x.trim()).filter(Boolean).map(field=>({field})),metrics:JSON.parse($('metrics').value)}}catch(e){$('out').textContent='Neplatný JSON v metrikách: '+e;return}};let r=await fetch('/ui/api/'+(k==='saved'?'saved':'query'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadStreams(){let r=await fetch('/ui/api/streams?server_id='+$('serverId').value);$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadAudit(){let p=new URLSearchParams();if($('auditSearch').value)p.set('q',$('auditSearch').value);if($('auditSource').value)p.set('source',$('auditSource').value);let r=await fetch('/ui/api/audit?'+p);$('auditOut').textContent=JSON.stringify(await r.json(),null,2)}
function setTheme(dark){document.body.classList.toggle('dark',dark);$('themeButton').textContent=dark?'Svetlý režim':'Tmavý režim';localStorage.setItem('graylog-mcp-theme',dark?'dark':'light')}
function toggleTheme(){setTheme(!document.body.classList.contains('dark'))}setTheme(localStorage.getItem('graylog-mcp-theme')==='dark');
function toggleMenu(){$('navLinks').classList.toggle('open')}
function showSection(id){document.querySelectorAll('.page-section').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.nav-links a').forEach(x=>x.classList.toggle('active',x.dataset.section===id));$('navLinks').classList.remove('open');if(id==='auditSection')loadAudit()}
document.querySelectorAll('.nav-links a').forEach(x=>x.onclick=e=>{e.preventDefault();history.replaceState(null,'','#'+x.getAttribute('href').slice(1));showSection(x.dataset.section)})
showSection(location.hash==='#clients'? 'clientsSection':location.hash==='#audit'?'auditSection':'graylogSection');loadServers();
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

@mcp.custom_route("/ui/api/queries", methods=["GET"])
async def ui_queries(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    return JSONResponse({"queries": [{"name": n, "description": catalog.get(n).get("description", "")} for n in catalog.names()]})

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
    data = await request.json(); q = catalog.render(data["name"], data.get("parameters", {})); kind = q.get("type", "messages"); selected_client = await get_client(data.get("server_id"))
    result = await selected_client.aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval")) if kind == "aggregate" else await selected_client.search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
    return JSONResponse(result)

@mcp.custom_route("/ui/api/streams", methods=["GET"])
async def ui_streams(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = request.query_params.get("server_id")
    return JSONResponse(await (await get_client(int(data) if data else None)).streams())

@mcp.custom_route("/ui/api/servers", methods=["GET", "POST"])
async def ui_servers(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    if request.method == "POST":
        try: return JSONResponse(await audit.add_server(**(await request.json())), status_code=201)
        except Exception as exc: return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse({"items": await audit.list_servers()})

@mcp.custom_route("/ui/api/servers/test", methods=["POST"])
async def ui_test_server(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = await request.json(); temporary = None
    try:
        server = await audit.get_server(int(data["server_id"])) if data.get("server_id") else data
        if not server or not server.get("url") or not server.get("api_token"):
            return JSONResponse({"success": False, "message": "Vyplň URL a Graylog API token."}, status_code=400)
        temporary = GraylogClient(settings, audit, server=server)
        result = await temporary.request("GET", "/api/cluster")
        return JSONResponse({"success": True, "message": "Pripojenie na Graylog API je funkčné.", "cluster": result})
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
    if name == "list_saved_queries": return {"queries": catalog.names()}
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
    """List names and descriptions of custom queries in queries.yaml."""
    return json.dumps({"queries": [{"name": n, "description": catalog.get(n).get("description", "")} for n in catalog.names()]}, ensure_ascii=False)

@mcp.tool()
async def run_saved_query(name: str, parameters: dict[str, Any] | None = None) -> str:
    """Run a query from queries.yaml with parameter overrides."""
    q = catalog.render(name, parameters or {})
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
