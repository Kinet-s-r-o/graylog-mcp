from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..auth.admin import AdminAuth, SESSION_COOKIE
from ..audit import AuditStore
from ..graylog import GraylogClient, GraylogError
from ..services.graylog_service import GraylogService
from ..services.query_service import QueryService
from ..settings import Settings
from .schemas import (
    AgentCreate,
    AgentUpdate,
    GraylogServerCreate,
    GraylogServerTest,
    GraylogServerUpdate,
    QueryDefinitionInput,
    SavedQueryRequest,
    UIQueryRequest,
    UISavedQueryRequest,
)

log = logging.getLogger(__name__)
WEBUI_DIR = Path(__file__).resolve().parents[1] / "webui"
QUERY_CSV_FIELDS = (
    "name", "description", "type", "query", "minutes", "limit", "interval",
    "group_by", "metrics", "defaults", "instructions", "fields",
)
QUERY_CSV_JSON_FIELDS = {"group_by", "metrics", "defaults", "fields"}


def _csv_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _csv_query_payload(row: dict[str, str | None], row_number: int) -> dict:
    if None in row:
        raise ValueError(f"CSV row {row_number} contains more values than the header")
    payload: dict = {}
    for field in QUERY_CSV_FIELDS:
        value = (row.get(field) or "").strip()
        if field in QUERY_CSV_JSON_FIELDS:
            if value:
                try:
                    payload[field] = json.loads(value)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"CSV row {row_number}: {field} contains invalid JSON") from exc
        elif field in {"minutes", "limit"}:
            if value:
                try:
                    payload[field] = int(value)
                except ValueError as exc:
                    raise ValueError(f"CSV row {row_number}: {field} must be an integer") from exc
        elif value:
            payload[field] = value
    return payload


class WebUIAssets:
    """Loads versioned static templates once; only the CSRF value is dynamic."""

    def __init__(self, root: Path = WEBUI_DIR):
        self.index = (root / "index.html").read_text(encoding="utf-8")
        self.login = (root / "login.html").read_text(encoding="utf-8")
        self.help = (root / "help.html").read_text(encoding="utf-8")

    def login_page(self, error: str = "", status_code: int = 200) -> HTMLResponse:
        message = f'<div class="error" role="alert">{error}</div>' if error else ""
        return HTMLResponse(self.login.replace("{error}", message), status_code=status_code)


def _safe_url(value: str) -> str:
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
        return f"Graylog API rejected the connection test for {endpoint}. Check the API token and Graylog permissions."
    if isinstance(exc, httpx.ConnectTimeout):
        return f"Connection to {endpoint} timed out.\nCheck that the server is reachable and increase Timeout (seconds) if needed."
    if isinstance(exc, httpx.ConnectError):
        return f"Could not connect to {endpoint}.\nCheck the URL, DNS, port, and firewall."
    if isinstance(exc, httpx.TimeoutException):
        return f"The request to {endpoint} timed out.\nCheck that Graylog is reachable and increase Timeout (seconds) if needed."
    return f"Connection test failed for {endpoint}. Check the server configuration and application logs."


def create_admin_router(
    settings: Settings,
    audit: AuditStore,
    graylog: GraylogService,
    queries: QueryService,
    auth: AdminAuth,
    assets: WebUIAssets,
) -> APIRouter:
    router = APIRouter()

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if auth.session(request):
            return RedirectResponse("/", status_code=303)
        return assets.login_page()

    @router.post("/login")
    async def login(request: Request):
        client_ip = auth.client_ip(request)
        if not auth.throttle.allowed(client_ip):
            return assets.login_page(
                "Too many failed sign-in attempts. Try again later.", status_code=429
            )
        body = (await request.body()).decode("utf-8", errors="replace")
        form = parse_qs(body)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if not auth.credentials_valid(username, password):
            auth.throttle.register_failure(client_ip)
            return assets.login_page("Invalid username or password.")
        auth.throttle.clear(client_ip)
        auth.sessions.revoke(request.cookies.get(SESSION_COOKIE))
        token, _session = auth.sessions.create()
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=settings.ui_session_ttl_seconds,
            httponly=True,
            secure=settings.ui_cookie_secure,
            samesite="strict",
            path="/",
        )
        return response

    @router.post("/logout")
    async def logout(request: Request, _session=Depends(auth.require)):
        auth.sessions.revoke(request.cookies.get(SESSION_COOKIE))
        response = JSONResponse({"signed_out": True})
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=settings.ui_cookie_secure,
            samesite="strict",
        )
        return response

    @router.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        session = auth.session(request)
        if not session:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(assets.index.replace("__CSRF_TOKEN__", session.csrf_token))

    @router.get("/ui/help", response_class=HTMLResponse)
    async def help_page(request: Request):
        if not auth.session(request):
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(assets.help)

    admin = APIRouter(prefix="/ui/api", dependencies=[Depends(auth.require)])

    @admin.get("/queries")
    async def list_queries():
        return {"queries": await audit.list_queries()}

    @admin.post("/queries")
    async def save_query(body: QueryDefinitionInput):
        data = body.model_dump()
        name = data.pop("name")
        return await audit.save_query(name, data)

    @admin.get("/queries/export")
    async def export_queries():
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=QUERY_CSV_FIELDS, lineterminator="\r\n")
        writer.writeheader()
        for query in await audit.list_queries():
            row = {field: query.get(field, "") for field in QUERY_CSV_FIELDS}
            for field in QUERY_CSV_JSON_FIELDS:
                row[field] = _csv_json(query.get(field, [] if field != "defaults" else {}))
            for field in ("minutes", "limit"):
                row[field] = "" if query.get(field) is None else str(query[field])
            writer.writerow(row)
        return Response(
            content="\ufeff" + output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="query-rules.csv"'},
        )

    @admin.post("/queries/import")
    async def import_queries(request: Request):
        try:
            text = (await request.body()).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="CSV must use UTF-8 encoding.") from exc
        if not text.strip():
            raise HTTPException(status_code=400, detail="CSV file is empty.")
        reader = csv.DictReader(io.StringIO(text))
        headers = reader.fieldnames or []
        missing = {field for field in ("name", "query") if field not in headers}
        if missing:
            raise HTTPException(status_code=400, detail=f"CSV is missing required columns: {', '.join(sorted(missing))}")
        validated: list[tuple[str, dict]] = []
        try:
            for row_number, row in enumerate(reader, start=2):
                if not any((value or "").strip() for value in row.values() if value is not None):
                    continue
                payload = _csv_query_payload(row, row_number)
                model = QueryDefinitionInput.model_validate(payload)
                data = model.model_dump()
                name = data.pop("name")
                validated.append((name, data))
        except ValueError as exc:
            detail = str(exc)
            if not detail.startswith("CSV row "):
                detail = f"CSV row {row_number}: {detail}"
            raise HTTPException(status_code=400, detail=detail) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"CSV row {row_number}: {exc}") from exc
        if not validated:
            raise HTTPException(status_code=400, detail="CSV contains no data rows.")
        for name, data in validated:
            await audit.save_query(name, data)
        return {"imported": len(validated), "names": [name for name, _ in validated]}

    @admin.delete("/queries")
    async def delete_query(name: str = Query(min_length=1, max_length=128)):
        clean_name = SavedQueryRequest(name=name).name
        await audit.remove_query(clean_name)
        return {"deleted": True}

    @admin.post("/query")
    async def execute_query(body: UIQueryRequest):
        client = await graylog.client(body.server_id)
        if body.group_by is not None:
            return await client.aggregate(
                body.query, body.minutes, body.group_by, body.metrics, body.interval
            )
        return await client.search_messages(body.query, body.minutes, body.limit)

    @admin.post("/saved")
    async def execute_saved(body: UISavedQueryRequest):
        return await queries.execute_saved(body.name, body.parameters, body.server_id)

    @admin.get("/streams")
    async def streams(server_id: int = Query(gt=0)):
        return await (await graylog.client(server_id)).streams()

    @admin.get("/servers")
    async def list_servers():
        return {"items": await audit.list_servers()}

    @admin.post("/servers", status_code=201)
    async def add_server(body: GraylogServerCreate):
        return await audit.add_server(**body.model_dump())

    @admin.put("/servers")
    async def update_server(body: GraylogServerUpdate):
        data = body.model_dump()
        server_id = data.pop("server_id")
        result = await audit.update_server(server_id, **data)
        await graylog.invalidate(server_id)
        return result

    @admin.delete("/servers")
    async def delete_server(server_id: int = Query(alias="id", gt=0)):
        await audit.remove_server(server_id)
        await graylog.invalidate(server_id)
        return {"deleted": True}

    @admin.post("/servers/test")
    async def test_server(body: GraylogServerTest):
        temporary = None
        server: dict = {}
        try:
            data = body.model_dump(exclude_none=True)
            stored = await audit.get_server(data["server_id"]) if data.get("server_id") else None
            server = dict(stored or {})
            for field in ("url", "api_token", "verify_tls", "timeout_seconds"):
                if field in data:
                    server[field] = data[field]
            if not server.get("url") or not server.get("api_token"):
                raise HTTPException(status_code=400, detail="Enter a URL and Graylog API token.")
            temporary = GraylogClient(settings, audit, server=server)
            result = await temporary.request("GET", "/api/cluster")
            return {
                "success": True,
                "message": "The Graylog API connection is working.",
                "cluster": result,
            }
        except HTTPException:
            raise
        except Exception as exc:
            endpoint = server.get("url", body.url or "")
            log.warning("Graylog connection test failed for %s", _safe_url(endpoint), exc_info=True)
            return JSONResponse(
                {"success": False, "message": _connection_error_message(exc, endpoint)},
                status_code=502,
            )
        finally:
            if temporary:
                await temporary.close()

    @admin.get("/agents")
    async def list_agents():
        return {"items": await audit.list_agents()}

    @admin.post("/agents", status_code=201)
    async def add_agent(body: AgentCreate):
        data = body.model_dump()
        data["server_id"] = data.pop("graylog_server_id")
        return await audit.add_agent(**data)

    @admin.put("/agents")
    async def update_agent(body: AgentUpdate):
        data = body.model_dump()
        agent_id = data.pop("agent_id")
        data["server_id"] = data.pop("graylog_server_id")
        return await audit.update_agent(agent_id, **data)

    @admin.delete("/agents")
    async def delete_agent(agent_id: int = Query(alias="id", gt=0)):
        await audit.remove_agent(agent_id)
        return {"deleted": True}

    @admin.get("/audit")
    async def audit_log(
        q: str | None = None,
        source: str | None = None,
        limit: int = Query(25, ge=1, le=500),
        page: int = Query(1, ge=1),
    ):
        total = await audit.count_recent(q, source)
        return {
            "items": await audit.recent(limit, q, source, (page - 1) * limit),
            "total": total,
            "page": page,
            "page_size": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }

    router.include_router(admin)
    return router
