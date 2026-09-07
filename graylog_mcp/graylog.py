from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import Any
import httpx

from .config import Settings
from .audit import stopwatch
from .security import agent_context


class GraylogError(RuntimeError):
    pass


def _timerange(minutes: int) -> dict[str, Any]:
    return {"type": "relative", "range": max(60, minutes * 60)}


def _absolute_timerange(start: datetime, end: datetime) -> dict[str, Any]:
    return {
        "type": "absolute",
        "from": start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "to": end.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _message_item(item: Any) -> dict[str, Any]:
    if isinstance(item, dict) and isinstance(item.get("message"), dict):
        return dict(item["message"])
    return dict(item) if isinstance(item, dict) else {"message": str(item)}


def normalize_messages(raw: dict[str, Any], query: str, minutes: int, limit: int) -> dict[str, Any]:
    items = [_message_item(item) for item in raw.get("messages", [])]
    total = raw.get("total_messages", raw.get("total"))
    result_count = int(total) if isinstance(total, int) else len(items)
    return {
        "query": query,
        "time_range_minutes": minutes,
        "result_count": result_count,
        "truncated": result_count >= limit,
        "items": items,
    }


def normalize_aggregate(raw: dict[str, Any], query: str, minutes: int) -> dict[str, Any]:
    rows = raw.get("datarows", raw.get("rows", []))
    schema = raw.get("schema", [])
    groups = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict):
            groups.append(dict(row))
        elif isinstance(row, list) and isinstance(schema, list):
            groups.append({str(column.get("name", index)): value for index, (column, value) in enumerate(zip(schema, row)) if isinstance(column, dict)})
    return {
        "query": query,
        "time_range_minutes": minutes,
        "result_count": len(groups),
        "truncated": False,
        "groups": groups,
    }


def _aggregate_count(result: dict[str, Any]) -> int | None:
    total = 0
    found = False
    for group in result.get("groups", []):
        for key, value in group.items():
            if str(key).lower() in {"count", "count_count"} and isinstance(value, (int, float)):
                total += int(value)
                found = True
    return total if found else None


_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.IGNORECASE)
_HEX_RE = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{16,}\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\b\d+\b")
_QUOTED_RE = re.compile(r"(['\"]).*?\1")


def normalize_error_message(value: str) -> str:
    value = _UUID_RE.sub("<UUID>", value)
    value = _HEX_RE.sub("<HEX>", value)
    value = _QUOTED_RE.sub("<VALUE>", value)
    value = _NUMBER_RE.sub("<N>", value)
    return " ".join(value.split())[:500]


class GraylogClient:
    def __init__(self, settings: Settings, audit: Any | None = None, *, server: dict | None = None, metrics=None):
        self.settings = settings
        self.audit = audit
        self.metrics = metrics
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

    async def request(self, method: str, path: str, *, params=None, json=None,
                      query_rule: str | None = None) -> Any:
        started = stopwatch()
        context = agent_context.get() or {}
        agent_id = context.get("agent_id")
        client_ip = context.get("client_ip")
        try:
            response = await self.client.request(method, path, params=params, json=json)
            if response.is_error:
                raise GraylogError(f"Graylog API returned HTTP {response.status_code} for {path}")
            result = response.json() if response.content else {}
            if self.metrics:
                self.metrics.inc("graylog_mcp_graylog_requests_total")
                self.metrics.inc("graylog_mcp_graylog_latency_ms_total", int((stopwatch()-started)*1000))
            if self.audit:
                audit_request = {"params": params, "json": json}
                if query_rule:
                    audit_request["query_rule"] = query_rule
                await self.audit.record(source="graylog", operation=f"{method} {path}", request=audit_request, response=result, status_code=response.status_code, duration_ms=(stopwatch()-started)*1000, agent_id=agent_id, client_ip=client_ip)
            return result
        except Exception as exc:
            if self.metrics:
                self.metrics.inc("graylog_mcp_graylog_errors_total")
            if self.audit:
                audit_request = {"params": params, "json": json}
                if query_rule:
                    audit_request["query_rule"] = query_rule
                await self.audit.record(source="graylog", operation=f"{method} {path}", request=audit_request, status_code=getattr(locals().get("response", None), "status_code", None), duration_ms=(stopwatch()-started)*1000, success=False, error=str(exc), agent_id=agent_id, client_ip=client_ip)
            raise

    async def search_messages(self, query: str, minutes: int = 15, limit: int = 50,
                              fields: list[str] | None = None,
                              query_rule: str | None = None,
                              compact: bool = False):
        limit = max(1, min(limit, self.settings.graylog_max_limit))
        body = {"query": query, "size": limit, "sort": "timestamp", "sort_order": "desc",
                "timerange": _timerange(minutes)}
        if fields:
            body["fields"] = fields
        if query_rule:
            raw = await self.request("POST", "/api/search/messages", json=body, query_rule=query_rule)
        else:
            raw = await self.request("POST", "/api/search/messages", json=body)
        return normalize_messages(raw, query, minutes, limit) if compact else raw

    async def _search_window(self, query: str, start: datetime, end: datetime, limit: int,
                             fields: list[str] | None = None, compact: bool = False):
        limit = max(1, min(limit, self.settings.graylog_max_limit))
        body: dict[str, Any] = {
            "query": query, "size": limit, "sort": "timestamp", "sort_order": "desc",
            "timerange": _absolute_timerange(start, end),
        }
        if fields:
            body["fields"] = fields
        raw = await self.request("POST", "/api/search/messages", json=body)
        return normalize_messages(raw, query, max(1, int((end - start).total_seconds() / 60)), limit) if compact else raw

    async def aggregate(self, query: str, minutes: int = 60, group_by: list[dict[str, Any]] | None = None,
                        metrics: list[dict[str, Any]] | None = None, interval: str | None = None,
                        query_rule: str | None = None, compact: bool = False):
        body = {"query": query, "timerange": _timerange(minutes),
                "group_by": list(group_by or []), "metrics": list(metrics or [{"function": "count", "id": "count"}]),
                }
        if interval:
            body["group_by"].append({"field": "timestamp", "timeunit": interval})
        if query_rule:
            raw = await self.request("POST", "/api/search/aggregate", json=body, query_rule=query_rule)
        else:
            raw = await self.request("POST", "/api/search/aggregate", json=body)
        return normalize_aggregate(raw, query, minutes) if compact else raw

    async def _aggregate_window(self, query: str, start: datetime, end: datetime,
                                group_by: list[dict[str, Any]] | None = None,
                                metrics: list[dict[str, Any]] | None = None,
                                interval: str | None = None):
        body: dict[str, Any] = {
            "query": query,
            "timerange": _absolute_timerange(start, end),
            "group_by": list(group_by or []),
            "metrics": list(metrics or [{"function": "count", "id": "count"}]),
        }
        if interval:
            body["group_by"].append({"field": "timestamp", "timeunit": interval})
        raw = await self.request("POST", "/api/search/aggregate", json=body)
        return normalize_aggregate(raw, query, max(1, int((end - start).total_seconds() / 60)))

    async def streams(self):
        return await self.request("GET", "/api/streams", params={"page": 1, "per_page": 1000})

    async def search_error_patterns(self, query: str, minutes: int = 60, limit: int = 50):
        result = await self.search_messages(
            query, minutes, limit, ["timestamp", "message", "level", "service", "source", "host"], compact=True
        )
        patterns: dict[str, dict[str, Any]] = {}
        for item in result["items"]:
            message = str(item.get("message", ""))
            pattern = normalize_error_message(message)
            entry = patterns.setdefault(pattern, {"pattern": pattern, "count": 0, "sample": item, "services": set()})
            entry["count"] += 1
            if item.get("service"):
                entry["services"].add(item["service"])
        ranked = sorted(patterns.values(), key=lambda item: item["count"], reverse=True)
        for item in ranked:
            item["services"] = sorted(item["services"])
        return {**result, "patterns": ranked[:limit], "result_count": len(ranked), "truncated": len(ranked) > limit}

    async def compare_time_windows(self, query: str, minutes: int = 60,
                                   group_by: list[dict[str, Any]] | None = None,
                                   metrics: list[dict[str, Any]] | None = None):
        end = datetime.now(timezone.utc)
        current_start = end - timedelta(minutes=minutes)
        previous_start = current_start - timedelta(minutes=minutes)
        current, previous = await asyncio.gather(
            self._aggregate_window(query, current_start, end, group_by, metrics),
            self._aggregate_window(query, previous_start, current_start, group_by, metrics),
        )
        current_count = _aggregate_count(current)
        previous_count = _aggregate_count(previous)
        return {
            "query": query,
            "window_minutes": minutes,
            "current": current,
            "previous": previous,
            "count_delta": (
                current_count - previous_count
                if current_count is not None and previous_count is not None
                else current["result_count"] - previous["result_count"]
            ),
            "count_is_group_count": current_count is None or previous_count is None,
        }

    async def get_log_context(self, timestamp: str, query: str = "*", before: int = 5, after: int = 5,
                              correlation_id: str | None = None):
        try:
            point = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 value") from exc
        point = point.astimezone(timezone.utc)
        actual_query = query
        if correlation_id:
            actual_query = f"({query}) AND correlation_id:{correlation_id}"
        result = await self._search_window(
            actual_query, point - timedelta(minutes=before), point + timedelta(minutes=after),
            limit=100, fields=["timestamp", "message", "level", "service", "source", "host", "correlation_id"], compact=True
        )
        return {**result, "center_timestamp": point.isoformat().replace("+00:00", "Z"), "before_minutes": before, "after_minutes": after}
