from __future__ import annotations

from typing import Any
import httpx

from .config import Settings
from .audit import AuditStore, stopwatch


class GraylogError(RuntimeError):
    pass


class GraylogClient:
    def __init__(self, settings: Settings, audit: AuditStore | None = None, *, server: dict | None = None):
        self.settings = settings
        self.audit = audit
        server = server or {}
        self.client = httpx.AsyncClient(
            base_url=(server.get("url") or settings.normalized_graylog_url or "http://invalid-graylog"),
            # Graylog access tokens use HTTP Basic Auth as TOKEN:token.
            auth=(server.get("api_token") or settings.graylog_api_token or "invalid-token", "token"),
            verify=server.get("verify_tls", settings.graylog_verify_tls),
            timeout=server.get("timeout_seconds", settings.graylog_timeout_seconds),
            headers={"Accept": "application/json", "X-Requested-By": "graylog-mcp"},
        )

    async def close(self):
        await self.client.aclose()

    async def request(self, method: str, path: str, *, params=None, json=None) -> Any:
        started = stopwatch()
        try:
            response = await self.client.request(method, path, params=params, json=json)
            if response.is_error:
                detail = response.text[:1000]
                raise GraylogError(f"Graylog API {response.status_code} at {path}: {detail}")
            result = response.json() if response.content else {}
            if self.audit:
                await self.audit.record(source="graylog", operation=f"{method} {path}", request={"params": params, "json": json}, response=result, status_code=response.status_code, duration_ms=(stopwatch()-started)*1000)
            return result
        except Exception as exc:
            if self.audit:
                await self.audit.record(source="graylog", operation=f"{method} {path}", request={"params": params, "json": json}, status_code=getattr(locals().get("response", None), "status_code", None), duration_ms=(stopwatch()-started)*1000, success=False, error=str(exc))
            raise

    async def search_messages(self, query: str, minutes: int = 15, limit: int = 100, fields: list[str] | None = None):
        limit = max(1, min(limit, self.settings.graylog_max_limit))
        body = {"query": query, "size": limit, "sort": "timestamp", "sort_order": "desc",
                "timerange": {"type": "relative", "range": max(60, minutes * 60)}}
        if fields:
            body["fields"] = fields
        return await self.request("POST", "/api/search/messages", json=body)

    async def aggregate(self, query: str, minutes: int = 60, group_by: list[dict[str, Any]] | None = None,
                        metrics: list[dict[str, Any]] | None = None, interval: str | None = None):
        body = {"query": query, "timerange": {"type": "relative", "range": max(60, minutes * 60)},
                "group_by": group_by or [], "metrics": metrics or [{"function": "count", "id": "count"}],
                }
        if interval:
            body["group_by"].append({"field": "timestamp", "timeunit": interval})
        return await self.request("POST", "/api/search/aggregate", json=body)

    async def streams(self):
        return await self.request("GET", "/api/streams", params={"page": 1, "per_page": 1000})
