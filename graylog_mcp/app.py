from __future__ import annotations

import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, PlainTextResponse, Response
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
from .services.adapters import GraylogOperations, MCPToolAdapter, RESTToolAdapter
from .services.admin_service import AdminService
from .settings import Settings
from .api.versioning import API_VERSION_HEADER, API_VERSION
from .observability import MetricsRegistry

log = logging.getLogger(__name__)
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "search_messages", "description": "Search Graylog messages. Use a narrow time range and fields; results are compact and include truncation metadata.", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "Lucene query"}, "minutes": {"type": "integer", "minimum": 1, "maximum": 525600, "default": 15}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50}, "fields": {"type": "array", "items": {"type": "string"}}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "aggregate", "description": "Aggregate Graylog data by fields and metrics. Prefer this before requesting raw messages.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer", "minimum": 1, "maximum": 525600, "default": 60}, "group_by": {"type": "array", "items": {"type": "object"}}, "metrics": {"type": "array", "items": {"type": "object"}}, "interval": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "list_streams", "description": "List Graylog streams.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "list_saved_queries", "description": "List managed query templates and their intended use.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "run_saved_query", "description": "Run a managed Graylog query template by name.", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "parameters": {"type": "object"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "search_error_patterns", "description": "Find and rank normalized recurring error message patterns with representative samples.", "parameters": {"type": "object", "properties": {"query": {"type": "string", "default": "level:3 OR level:4 OR level:5"}, "minutes": {"type": "integer", "minimum": 1, "default": 60}, "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "compare_time_windows", "description": "Compare the current time window with the immediately preceding window.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "minutes": {"type": "integer", "minimum": 1, "default": 60}, "group_by": {"type": "array", "items": {"type": "object"}}, "metrics": {"type": "array", "items": {"type": "object"}}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "get_log_context", "description": "Retrieve log events around an ISO-8601 timestamp, optionally narrowed by correlation ID.", "parameters": {"type": "object", "properties": {"timestamp": {"type": "string"}, "query": {"type": "string", "default": "*"}, "before": {"type": "integer", "minimum": 0, "maximum": 60, "default": 5}, "after": {"type": "integer", "minimum": 0, "maximum": 60, "default": 5}, "correlation_id": {"type": "string"}}, "required": ["timestamp"]}}},
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


def create_app(
    configuration: Settings | None = None,
    *,
    repository: Any | None = None,
    secret_provider: Any | None = None,
    session_store: Any | None = None,
) -> FastAPI:
    settings = configuration or Settings()
    logging.basicConfig(level=settings.log_level)
    metrics = MetricsRegistry()
    audit = repository or AuditStore(
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
        secret_provider=secret_provider,
        metrics=metrics,
    )
    catalog = QueryCatalog(settings.query_catalog_path)
    trusted_proxies = parse_networks(settings.trusted_proxy_networks)
    admin_auth = create_admin_auth(settings, trusted_proxies, sessions=session_store)
    agent_auth = AgentAuth(audit, trusted_proxies)
    graylog = GraylogService(settings, audit, metrics=metrics)
    queries = QueryService(settings, audit, graylog)
    operations = GraylogOperations(graylog, queries)
    mcp_adapter = MCPToolAdapter(operations)
    admin_service = AdminService(audit, graylog, queries)
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
        """Search compact Graylog messages with result count and truncation metadata."""
        result = await mcp_adapter.invoke(
            "search_messages",
            {"query": query, "minutes": minutes, "limit": limit or settings.graylog_default_limit, "fields": fields},
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
        result = await mcp_adapter.invoke(
            "aggregate",
            {"query": query, "minutes": minutes, "group_by": group_by, "metrics": metrics, "interval": interval},
        )
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    async def list_streams() -> str:
        """List Graylog streams."""
        return json.dumps(await mcp_adapter.invoke("list_streams", {}), ensure_ascii=False)

    @mcp.tool()
    async def list_saved_queries() -> str:
        """List database-managed query templates and their agent instructions."""
        return json.dumps(await mcp_adapter.invoke("list_saved_queries", {}), ensure_ascii=False)

    @mcp.tool()
    async def run_saved_query(
        name: str, parameters: dict[str, Any] | None = None
    ) -> str:
        """Run a database-managed query template with parameter overrides."""
        return json.dumps(
            await mcp_adapter.invoke("run_saved_query", {"name": name, "parameters": parameters or {}}),
            ensure_ascii=False,
        )

    @mcp.tool()
    async def search_error_patterns(
        query: str = "level:3 OR level:4 OR level:5", minutes: int = 60, limit: int = 20
    ) -> str:
        """Find recurring normalized error patterns and representative samples."""
        return json.dumps(
            await mcp_adapter.invoke("search_error_patterns", {"query": query, "minutes": minutes, "limit": limit}),
            ensure_ascii=False,
        )

    @mcp.tool()
    async def compare_time_windows(
        query: str, minutes: int = 60, group_by: list[dict] | None = None,
        metrics: list[dict] | None = None,
    ) -> str:
        """Compare current and previous Graylog windows using the same query."""
        return json.dumps(
            await mcp_adapter.invoke("compare_time_windows", {"query": query, "minutes": minutes, "group_by": group_by, "metrics": metrics}),
            ensure_ascii=False,
        )

    @mcp.tool()
    async def get_log_context(
        timestamp: str, query: str = "*", before: int = 5, after: int = 5,
        correlation_id: str | None = None,
    ) -> str:
        """Retrieve log events around a timestamp or correlation ID."""
        return json.dumps(
            await mcp_adapter.invoke("get_log_context", {"timestamp": timestamp, "query": query, "before": before, "after": after, "correlation_id": correlation_id}),
            ensure_ascii=False,
        )

    @mcp.tool()
    async def ask_graylog(question: str) -> str:
        """Answer a Graylog question using OpenAI to orchestrate Graylog tools."""
        if not settings.openai_api_key:
            return "OpenAI is not configured. Use search_messages, aggregate or run_saved_query directly."
        return await OpenAIAgent(settings, TOOL_SCHEMAS, audit, metrics).ask(question, execute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if hasattr(audit, "open"):
            await audit.open()
        if hasattr(audit, "seed_queries"):
            await audit.seed_queries(catalog.queries)
        try:
            # Mounted Starlette applications do not run their own lifespan.
            # FastMCP's Streamable HTTP transport therefore has to be started
            # explicitly from the parent FastAPI application's lifespan.
            async with mcp.session_manager.run():
                yield
        finally:
            await graylog.close()
            if hasattr(audit, "close"):
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
        "operations": operations,
        "mcp_adapter": mcp_adapter,
        "admin_service": admin_service,
        "admin_auth": admin_auth,
        "agent_auth": agent_auth,
        "tools": {
            "search_messages": search_messages,
            "aggregate": aggregate,
            "list_streams": list_streams,
            "list_saved_queries": list_saved_queries,
            "run_saved_query": run_saved_query,
            "search_error_patterns": search_error_patterns,
            "compare_time_windows": compare_time_windows,
            "get_log_context": get_log_context,
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
        audit_agent_id = None
        audit_client_ip = None
        audit_mcp_request = False
        audit_mcp_payload = None
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
                    audit_client_ip = agent_auth.client_ip(request)
                    agent_token = agent_context.set(context)
                    audit_agent_id = context.get("agent_id")
                    audit_mcp_request = True
                    if request.method not in {"GET", "HEAD"}:
                        raw_body = await request.body()
                        if raw_body:
                            try:
                                audit_mcp_payload = json.loads(raw_body)
                            except (TypeError, ValueError):
                                audit_mcp_payload = raw_body.decode("utf-8", errors="replace")
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
            metrics.inc("graylog_mcp_http_requests_total")
            if response.status_code in {401, 403}:
                metrics.inc("graylog_mcp_auth_failures_total")
        finally:
            if audit_mcp_request:
                # FastMCP is mounted below this middleware, so the protocol
                # request itself otherwise never reaches the audit store.
                # Do not consume request.body(): the mounted MCP transport
                # still needs to read it.
                await audit.record(
                    source="mcp",
                    operation=f"{request.method} {path}",
                    request={
                        "query": dict(request.query_params),
                        "content_type": request.headers.get("content-type"),
                        "body": audit_mcp_payload,
                    },
                    status_code=response.status_code if response is not None else None,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    success=response is not None and response.status_code < 400,
                    agent_id=audit_agent_id,
                    client_ip=audit_client_ip,
                )
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
        if path.startswith("/api/v1") or path.startswith(settings.mcp_path):
            response.headers.setdefault(API_VERSION_HEADER, API_VERSION)
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

    @app.get("/ready", tags=["System"])
    async def readiness():
        if not getattr(audit, "db", None):
            return JSONResponse(
                {"status": "not_ready", "reason": "database_not_open"}, status_code=503
            )
        return {"status": "ready", "service": "custom-graylog-mcp"}

    @app.get("/metrics", tags=["System"])
    async def metrics_endpoint():
        return Response(
            metrics.render(active_sessions=len(admin_auth.sessions)),
            media_type="text/plain; version=0.0.4",
        )

    app.include_router(
        create_agent_router(settings, graylog, queries, agent_auth, RESTToolAdapter(operations))
    )
    app.include_router(
        create_admin_router(
            settings, audit, graylog, queries, admin_auth, assets, admin_service
        )
    )
    app.mount("/ui/assets", StaticFiles(directory=WEBUI_DIR), name="webui-assets")
    app.mount("/", mcp.streamable_http_app())
    return app
