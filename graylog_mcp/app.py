from __future__ import annotations

import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.staticfiles import StaticFiles

from .api.admin_routes import WEBUI_DIR, WebUIAssets, create_admin_router
from .api.agent_routes import create_agent_router
from .audit import AuditStore
from .auth.admin import create_admin_auth
from .auth.agent import AgentAuth
from .catalog import QueryCatalog
from .openai_agent import OpenAIAgent
from .security import agent_context, ip_allowed, parse_networks
from .services.graylog_service import GraylogService
from .services.query_service import QueryService
from .settings import Settings

log = logging.getLogger(__name__)
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "search_messages", "description": "Search Graylog messages using a Lucene query", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "aggregate", "description": "Aggregate Graylog data by fields and metrics", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer"}, "group_by": {"type": "array", "items": {"type": "object"}}, "metrics": {"type": "array", "items": {"type": "object"}}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "list_saved_queries", "description": "List custom queries from the query catalog", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "run_saved_query", "description": "Run a managed Graylog query template by name", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "parameters": {"type": "object"}}, "required": ["name"]}}},
]


def _listener_port(request: Request) -> int | None:
    address = request.scope.get("server")
    try:
        return int(address[1]) if address else None
    except (IndexError, TypeError, ValueError):
        return None


def _is_agent_path(path: str, settings: Settings) -> bool:
    return (
        path.startswith(settings.mcp_path)
        or path.startswith("/api/v1")
        or path in {"/docs", "/openapi.json", "/redoc"}
        or path.startswith("/docs/")
    )


def _is_webui_path(path: str) -> bool:
    return path in {"/", "/login", "/logout"} or path.startswith("/ui")


def _error_payload(request: Request, code: str, detail: str) -> dict[str, str]:
    return {
        "code": code,
        "detail": detail,
        "request_id": getattr(request.state, "request_id", ""),
    }


def _validation_detail(exc: ValidationError | RequestValidationError) -> str:
    errors = exc.errors(include_url=False, include_context=False, include_input=False)
    if not errors:
        return "Request validation failed"
    error = errors[0]
    field = ".".join(str(item) for item in error.get("loc", ()) if item != "body")
    return f"{field}: {error['msg']}" if field else error["msg"]


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse(
            _error_payload(request, "validation_error", _validation_detail(exc)), status_code=422
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        detail = str(exc.detail) if exc.detail else "Request failed"
        code = "not_found" if exc.status_code == 404 else "request_error"
        return JSONResponse(_error_payload(request, code, detail), status_code=exc.status_code)

    @app.exception_handler(ValueError)
    @app.exception_handler(KeyError)
    async def value_error(request: Request, exc: Exception):
        return JSONResponse(
            _error_payload(request, "invalid_request", str(exc).strip("'")), status_code=400
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        log.exception(
            "Unhandled request error",
            extra={"request_id": getattr(request.state, "request_id", "")},
        )
        return JSONResponse(
            _error_payload(request, "internal_error", "Request could not be processed"),
            status_code=500,
        )


def create_app(configuration: Settings | None = None) -> FastAPI:
    settings = configuration or Settings()
    logging.basicConfig(level=settings.log_level)
    audit = AuditStore(
        settings.audit_db_path,
        settings.audit_retention_days,
        settings.audit_max_rows,
        settings.audit_max_payload_chars,
        secret_encryption_key=(
            settings.secret_encryption_key.get_secret_value()
            if settings.secret_encryption_key
            else None
        ),
        redact_fields=settings.audit_redacted_field_names,
    )
    catalog = QueryCatalog(settings.query_catalog_path)
    trusted_proxies = parse_networks(settings.trusted_proxy_networks)
    admin_auth = create_admin_auth(settings, trusted_proxies)
    agent_auth = AgentAuth(audit, trusted_proxies)
    graylog = GraylogService(settings, audit)
    queries = QueryService(settings, audit, graylog)
    assets = WebUIAssets()
    mcp = FastMCP(
        "custom-graylog",
        host=settings.mcp_host,
        port=settings.mcp_port,
        streamable_http_path=settings.mcp_path,
    )

    async def execute(name: str, args: dict[str, Any]):
        return await queries.execute_tool(name, args)

    @mcp.tool()
    async def search_messages(
        query: str,
        minutes: int = 15,
        limit: int | None = None,
        fields: list[str] | None = None,
    ) -> str:
        """Search Graylog messages with a Lucene query over a relative time window."""
        client = await graylog.client()
        result = await client.search_messages(
            query, minutes, limit or settings.graylog_default_limit, fields
        )
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    async def aggregate(
        query: str,
        minutes: int = 60,
        group_by: list[dict] | None = None,
        metrics: list[dict] | None = None,
        interval: str = "5m",
    ) -> str:
        """Run a Graylog aggregation. Metrics follow Graylog's aggregate API format."""
        result = await (await graylog.client()).aggregate(
            query, minutes, group_by, metrics, interval
        )
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    async def list_streams() -> str:
        """List Graylog streams."""
        return json.dumps(await (await graylog.client()).streams(), ensure_ascii=False)

    @mcp.tool()
    async def list_saved_queries() -> str:
        """List database-managed query templates and their agent instructions."""
        return json.dumps({"queries": await queries.summaries()}, ensure_ascii=False)

    @mcp.tool()
    async def run_saved_query(
        name: str, parameters: dict[str, Any] | None = None
    ) -> str:
        """Run a database-managed query template with parameter overrides."""
        return json.dumps(
            await queries.execute_saved(name, parameters or {}), ensure_ascii=False
        )

    @mcp.tool()
    async def ask_graylog(question: str) -> str:
        """Answer a Graylog question using OpenAI to orchestrate Graylog tools."""
        if not settings.openai_api_key:
            return "OpenAI is not configured. Use search_messages, aggregate or run_saved_query directly."
        return await OpenAIAgent(settings, TOOL_SCHEMAS, audit).ask(question, execute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await audit.open()
        await audit.seed_queries(catalog.queries)
        try:
            yield
        finally:
            await graylog.close()
            await audit.close()

    app = FastAPI(
        title="Custom Graylog MCP API",
        version="0.1.0",
        description="REST API for Graylog searches, aggregations and saved queries.",
        lifespan=lifespan,
    )
    app.state.runtime = {
        "settings": settings,
        "audit": audit,
        "catalog": catalog,
        "mcp": mcp,
        "graylog": graylog,
        "queries": queries,
        "admin_auth": admin_auth,
        "agent_auth": agent_auth,
        "tools": {
            "search_messages": search_messages,
            "aggregate": aggregate,
            "list_streams": list_streams,
            "list_saved_queries": list_saved_queries,
            "run_saved_query": run_saved_query,
            "ask_graylog": ask_graylog,
            "execute": execute,
        },
    }
    _install_error_handlers(app)

    @app.middleware("http")
    async def request_lifecycle(request: Request, call_next):
        started = time.perf_counter()
        supplied_request_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_request_id
            if REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else uuid.uuid4().hex
        )
        request.state.request_id = request_id
        path = request.url.path
        listener_port = _listener_port(request)
        response = None
        agent_token = None
        try:
            if listener_port not in {settings.mcp_port, settings.webui_port}:
                response = PlainTextResponse("Not Found", status_code=404)
            elif listener_port == settings.webui_port and _is_agent_path(path, settings):
                response = PlainTextResponse("Not Found", status_code=404)
            elif listener_port == settings.mcp_port and _is_webui_path(path):
                response = PlainTextResponse("Not Found", status_code=404)
            elif path.startswith(settings.mcp_path):
                authorization = request.headers.get("authorization", "")
                key = (
                    authorization.split(" ", 1)[1].strip()
                    if authorization.lower().startswith("bearer ")
                    else ""
                )
                context = await audit.authenticate_agent(key) if key else None
                if not context:
                    response = PlainTextResponse(
                        "Valid agent Bearer API key required", status_code=401
                    )
                elif not ip_allowed(
                    agent_auth.client_ip(request), context.get("allowed_ips", [])
                ):
                    response = PlainTextResponse(
                        "Agent IP address is not allowed", status_code=403
                    )
                else:
                    agent_token = agent_context.set(context)
                    response = await call_next(request)
            elif (
                (path.startswith("/ui/api/") or path == "/logout")
                and request.method not in {"GET", "HEAD", "OPTIONS"}
            ):
                if admin_auth.session(request) is None:
                    response = JSONResponse(
                        _error_payload(request, "unauthorized", "Authentication required"),
                        status_code=401,
                    )
                elif not admin_auth.valid_csrf(request):
                    response = JSONResponse(
                        _error_payload(
                            request, "csrf_failed", "Invalid or missing CSRF token"
                        ),
                        status_code=403,
                    )
                else:
                    response = await call_next(request)
            else:
                response = await call_next(request)
        finally:
            if agent_token is not None:
                agent_context.reset(agent_token)
        response.headers.setdefault("X-Request-ID", request_id)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self'; script-src 'self'",
        )
        if _is_webui_path(path):
            response.headers.setdefault("Cache-Control", "no-store")
        log.info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            )
        )
        return response

    @app.get("/health", tags=["System"])
    async def health():
        return {"status": "ok", "service": "custom-graylog-mcp"}

    app.include_router(create_agent_router(settings, graylog, queries, agent_auth))
    app.include_router(
        create_admin_router(settings, audit, graylog, queries, admin_auth, assets)
    )
    app.mount("/ui/assets", StaticFiles(directory=WEBUI_DIR), name="webui-assets")
    app.mount("/", mcp.streamable_http_app())
    return app
