from __future__ import annotations

import json
import logging
import base64
import hmac
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
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
client = GraylogClient(settings, audit)
catalog = QueryCatalog(settings.query_catalog_path)

TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "search_messages", "description": "Search Graylog messages using a Lucene query", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "aggregate", "description": "Aggregate Graylog data by fields and metrics", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "group_by": {"type": "array", "items": {"type": "object"}}, "metrics": {"type": "array", "items": {"type": "object"}}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "list_saved_queries", "description": "List custom queries from the query catalog", "parameters": {"type": "object", "properties": {}}}},
]

@asynccontextmanager
async def lifespan(_server):
    await audit.open()
    yield
    await audit.close()
    await client.close()

mcp = FastMCP("custom-graylog", host=settings.mcp_host, port=settings.mcp_port,
              streamable_http_path=settings.mcp_path, lifespan=lifespan)

UI_HTML = """<!doctype html>
<html lang="sk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Graylog MCP</title><style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#f5f7fa;color:#17202a;transition:background .2s,color .2s}
main{background:white;border:1px solid #d9e0e7;border-radius:10px;padding:1.25rem;box-shadow:0 2px 8px #0001;transition:background .2s,border-color .2s}
label{display:block;font-weight:600;margin:.8rem 0 .25rem}input,select,textarea,button{font:inherit;padding:.55rem;border:1px solid #b8c3ce;border-radius:5px;box-sizing:border-box;width:100%}
textarea{min-height:90px;font-family:ui-monospace,monospace}button{width:auto;background:#2563eb;color:white;border:0;cursor:pointer;margin-top:1rem}button.secondary{background:#566573}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:700px){.grid{grid-template-columns:1fr}}
pre{background:#111827;color:#d1fae5;padding:1rem;border-radius:6px;overflow:auto;min-height:180px}.muted{color:#64748b}.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem}.theme{background:#e2e8f0;color:#17202a;margin:0}
body.dark{background:#071426;color:#e5eefb}body.dark main{background:#0d2138;border-color:#1e456d}body.dark input,body.dark select,body.dark textarea{background:#102b48;color:#e5eefb;border-color:#32618e}body.dark .muted{color:#9db4cc}body.dark .theme{background:#21476e;color:#e5eefb}
</style></head><body><main><div class="topbar"><h1>Graylog MCP</h1><button class="theme" onclick="toggleTheme()" id="themeButton">Tmavý režim</button></div><p class="muted">Webové rozhranie pre testovanie Graylog dotazov.</p>
<label>Typ dotazu</label><select id="kind"><option value="search">Vyhľadávanie správ</option><option value="aggregate">Agregácia</option><option value="saved">Uložený dotaz</option></select>
<label id="savedLabel" hidden>Uložený dotaz</label><select id="saved" hidden></select>
<label>Graylog dotaz (Lucene)</label><textarea id="query" placeholder="level:3 OR service:api"></textarea>
<div class="grid"><div><label>Časové okno (minúty)</label><input id="minutes" type="number" value="60" min="1"></div><div><label>Limit správ</label><input id="limit" type="number" value="100" min="1"></div></div>
<label>Group by (len pre agregáciu, čiarkami oddelené)</label><input id="groupBy" placeholder="service,source">
<label>Metriky JSON (len pre agregáciu)</label><input id="metrics" value='[{"function":"count"}]'>
<button onclick="run()">Spustiť dotaz</button> <button class="secondary" onclick="loadStreams()">Načítať streamy</button>
<h2>Výsledok</h2><pre id="out">Pripravené.</pre>
<h2>Audit log</h2><div class="grid"><div><label>Fulltext audit logu</label><input id="auditSearch" placeholder="napr. authentication OR timeout"></div><div><label>Zdroj</label><select id="auditSource"><option value="">Všetky</option><option>graylog</option><option>openai</option><option>mcp</option></select></div></div>
<button class="secondary" onclick="loadAudit()">Vyhľadať v audit logu</button><pre id="auditOut">Audit log sa načíta po vyhľadaní.</pre></main><script>
const $=id=>document.getElementById(id); async function loadSaved(){let r=await fetch('/ui/api/queries');let d=await r.json();$('saved').innerHTML=d.queries.map(x=>`<option value="${x.name}">${x.name} — ${x.description}</option>`).join('')}
$('kind').onchange=()=>{let s=$('kind').value==='saved';$('saved').hidden=!s;$('savedLabel').hidden=!s};loadSaved();
async function run(){let k=$('kind').value,b={};if(k==='saved'){b={name:$('saved').value,parameters:{}}}else if(k==='search'){b={query:$('query').value,minutes:+$('minutes').value,limit:+$('limit').value}}else{try{b={query:$('query').value,minutes:+$('minutes').value,group_by:$('groupBy').value.split(',').map(x=>x.trim()).filter(Boolean).map(field=>({field})),metrics:JSON.parse($('metrics').value)}}catch(e){$('out').textContent='Neplatný JSON v metrikách: '+e;return}};let r=await fetch('/ui/api/'+(k==='saved'?'saved':'query'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadStreams(){let r=await fetch('/ui/api/streams');$('out').textContent=JSON.stringify(await r.json(),null,2)}
async function loadAudit(){let p=new URLSearchParams();if($('auditSearch').value)p.set('q',$('auditSearch').value);if($('auditSource').value)p.set('source',$('auditSource').value);let r=await fetch('/ui/api/audit?'+p);$('auditOut').textContent=JSON.stringify(await r.json(),null,2)}
function setTheme(dark){document.body.classList.toggle('dark',dark);$('themeButton').textContent=dark?'Svetlý režim':'Tmavý režim';localStorage.setItem('graylog-mcp-theme',dark?'dark':'light')}
function toggleTheme(){setTheme(!document.body.classList.contains('dark'))}setTheme(localStorage.getItem('graylog-mcp-theme')==='dark');
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
    data = await request.json()
    kind = "aggregate" if data.get("group_by") is not None else "search"
    result = await client.aggregate(data["query"], data.get("minutes", 60), data.get("group_by"), data.get("metrics")) if kind == "aggregate" else await client.search_messages(data["query"], data.get("minutes", 15), data.get("limit", settings.graylog_default_limit))
    return JSONResponse(result)

@mcp.custom_route("/ui/api/saved", methods=["POST"])
async def ui_saved(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    data = await request.json(); q = catalog.render(data["name"], data.get("parameters", {})); kind = q.get("type", "messages")
    result = await client.aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval")) if kind == "aggregate" else await client.search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
    return JSONResponse(result)

@mcp.custom_route("/ui/api/streams", methods=["GET"])
async def ui_streams(request: Request):
    if not _ui_authorized(request): return _ui_unauthorized()
    return JSONResponse(await client.streams())

async def execute(name: str, args: dict[str, Any]):
    if name == "search_messages": return await client.search_messages(**args)
    if name == "aggregate": return await client.aggregate(**args)
    if name == "list_saved_queries": return {"queries": catalog.names()}
    raise ValueError(f"Unsupported tool: {name}")

@mcp.tool()
async def search_messages(query: str, minutes: int = 15, limit: int | None = None, fields: list[str] | None = None) -> str:
    """Search Graylog messages with a Lucene query over a relative time window."""
    return json.dumps(await client.search_messages(query, minutes, limit or settings.graylog_default_limit, fields), ensure_ascii=False)

@mcp.tool()
async def aggregate(query: str, minutes: int = 60, group_by: list[str] | None = None, metrics: list[dict] | None = None, interval: str = "5m") -> str:
    """Run a Graylog aggregation. Metrics follow Graylog's aggregate API format."""
    return json.dumps(await client.aggregate(query, minutes, group_by, metrics, interval), ensure_ascii=False)

@mcp.tool()
async def list_streams() -> str:
    """List Graylog streams."""
    return json.dumps(await client.streams(), ensure_ascii=False)

@mcp.tool()
async def list_saved_queries() -> str:
    """List names and descriptions of custom queries in queries.yaml."""
    return json.dumps({"queries": [{"name": n, "description": catalog.get(n).get("description", "")} for n in catalog.names()]}, ensure_ascii=False)

@mcp.tool()
async def run_saved_query(name: str, parameters: dict[str, Any] | None = None) -> str:
    """Run a query from queries.yaml with parameter overrides."""
    q = catalog.render(name, parameters or {})
    kind = q.get("type", "messages")
    if kind == "aggregate": result = await client.aggregate(q["query"], q.get("minutes", 60), q.get("group_by"), q.get("metrics"), q.get("interval", "5m"))
    else: result = await client.search_messages(q["query"], q.get("minutes", 15), q.get("limit", settings.graylog_default_limit), q.get("fields"))
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

def main():
    mcp.run(transport="streamable-http")

if __name__ == "__main__": main()
