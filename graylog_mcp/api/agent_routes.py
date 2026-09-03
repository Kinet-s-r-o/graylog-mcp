from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth.agent import AgentAuth
from ..services.graylog_service import GraylogService
from ..services.query_service import QueryService
from ..settings import Settings
from .schemas import AggregateRequest, SavedQueryRequest, SearchRequest


def create_agent_router(
    settings: Settings, graylog: GraylogService, queries: QueryService, auth: AgentAuth
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.post("/search/messages", tags=["Graylog"])
    async def search_messages(body: SearchRequest, _agent=Depends(auth.require)):
        client = await graylog.client()
        return await client.search_messages(
            body.query, body.minutes, body.limit or settings.graylog_default_limit, body.fields
        )

    @router.post("/search/aggregate", tags=["Graylog"])
    async def aggregate(body: AggregateRequest, _agent=Depends(auth.require)):
        client = await graylog.client()
        return await client.aggregate(
            body.query, body.minutes, body.group_by, body.metrics, body.interval
        )

    @router.get("/streams", tags=["Graylog"])
    async def streams(_agent=Depends(auth.require)):
        return await (await graylog.client()).streams()

    @router.get("/queries", tags=["Saved queries"])
    async def saved_queries(_agent=Depends(auth.require)):
        return {"queries": await queries.summaries()}

    @router.post("/queries/run", tags=["Saved queries"])
    async def run_saved_query(body: SavedQueryRequest, _agent=Depends(auth.require)):
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
        total = await queries.audit.count_recent(q, source, agent_id)
        return {
            "items": await queries.audit.recent(
                limit, q, source, (page - 1) * limit, agent_id
            ),
            "total": total,
            "page": page,
            "page_size": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }

    return router

