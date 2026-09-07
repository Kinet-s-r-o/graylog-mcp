from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth.agent import AgentAuth
from ..services.graylog_service import GraylogService
from ..services.query_service import QueryService
from ..services.adapters import GraylogOperations, RESTToolAdapter
from ..settings import Settings
from .schemas import (
    AggregateRequest, CompareWindowsRequest, ErrorPatternRequest, LogContextRequest,
    SavedQueryRequest, SearchRequest,
)


def create_agent_router(
    settings: Settings, graylog: GraylogService, queries: QueryService, auth: AgentAuth,
    adapter: RESTToolAdapter | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    adapter = adapter or RESTToolAdapter(GraylogOperations(graylog, queries))

    @router.post("/search/messages", tags=["Graylog"])
    async def search_messages(body: SearchRequest, _agent=Depends(auth.require)):
        return await adapter.search_messages(
            query=body.query,
            minutes=body.minutes,
            limit=body.limit or settings.graylog_default_limit,
            fields=body.fields,
        )

    @router.post("/search/aggregate", tags=["Graylog"])
    async def aggregate(body: AggregateRequest, _agent=Depends(auth.require)):
        return await adapter.aggregate(
            query=body.query,
            minutes=body.minutes,
            group_by=body.group_by,
            metrics=body.metrics,
            interval=body.interval,
        )

    @router.get("/streams", tags=["Graylog"])
    async def streams(_agent=Depends(auth.require)):
        return await adapter.streams()

    @router.post("/search/error-patterns", tags=["Graylog"])
    async def error_patterns(body: ErrorPatternRequest, _agent=Depends(auth.require)):
        return await adapter.search_error_patterns(**body.model_dump())

    @router.post("/search/compare-windows", tags=["Graylog"])
    async def compare_windows(body: CompareWindowsRequest, _agent=Depends(auth.require)):
        return await adapter.compare_time_windows(**body.model_dump())

    @router.post("/search/context", tags=["Graylog"])
    async def log_context(body: LogContextRequest, _agent=Depends(auth.require)):
        return await adapter.get_log_context(**body.model_dump())

    @router.get("/queries", tags=["Saved queries"])
    async def saved_queries(_agent=Depends(auth.require)):
        queries.require_tool_access("list_saved_queries")
        return {"queries": await queries.summaries()}

    @router.post("/queries/run", tags=["Saved queries"])
    async def run_saved_query(body: SavedQueryRequest, _agent=Depends(auth.require)):
        queries.require_tool_access("run_saved_query")
        try:
            return await queries.execute_saved(body.name, body.parameters)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc

    @router.get("/audit", tags=["Audit"])
    async def audit_log(
        q: str | None = Query(None, description="FTS5 fulltext expression"),
        source: str | None = None,
        limit: int = Query(25, ge=1, le=500),
        page: int = Query(1, ge=1),
        agent=Depends(auth.require),
    ):
        agent_id = int(agent["agent_id"])
        total = await queries.audit_count(q, source, agent_id)
        return {
            "items": await queries.audit_recent(
                limit, q, source, (page - 1) * limit, agent_id
            ),
            "total": total,
            "page": page,
            "page_size": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }

    return router
