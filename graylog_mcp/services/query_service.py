from __future__ import annotations

import string
from typing import Any

from ..audit import AuditStore
from ..settings import Settings
from .graylog_service import GraylogService


class QueryService:
    """Renders and executes saved query definitions for every adapter."""

    def __init__(self, settings: Settings, audit: AuditStore, graylog: GraylogService):
        self.settings = settings
        self.audit = audit
        self.graylog = graylog

    def _render_value(self, value: Any, parameters: dict[str, Any]):
        if isinstance(value, str):
            return string.Template(value).safe_substitute(parameters)
        if isinstance(value, list):
            return [self._render_value(item, parameters) for item in value]
        if isinstance(value, dict):
            return {key: self._render_value(item, parameters) for key, item in value.items()}
        return value

    async def render(self, name: str, parameters: dict[str, Any]):
        definition = await self.audit.get_query(name)
        if not definition:
            raise KeyError(f"Unknown saved query '{name}'")
        values = {**definition.get("defaults", {}), **parameters}
        return self._render_value(definition, values)

    async def summaries(self):
        return [
            {
                "name": item["name"],
                "description": item.get("description", ""),
                "type": item.get("type", "messages"),
                "instructions": item.get("instructions", ""),
            }
            for item in await self.audit.list_queries()
        ]

    async def execute_saved(
        self, name: str, parameters: dict[str, Any], server_id: int | None = None
    ):
        query = await self.render(name, parameters)
        client = await self.graylog.client(server_id)
        if query.get("type", "messages") == "aggregate":
            return await client.aggregate(
                query["query"],
                query.get("minutes", 60),
                query.get("group_by"),
                query.get("metrics"),
                query.get("interval"),
                name,
            )
        return await client.search_messages(
            query["query"],
            query.get("minutes", 15),
            query.get("limit") or self.settings.graylog_default_limit,
            query.get("fields"),
            name,
        )

    async def execute_tool(self, name: str, args: dict[str, Any]):
        client = await self.graylog.client()
        if name == "search_messages":
            return await client.search_messages(**args)
        if name == "aggregate":
            return await client.aggregate(**args)
        if name == "list_saved_queries":
            return {"queries": await self.summaries()}
        if name == "run_saved_query":
            return await self.execute_saved(args["name"], args.get("parameters", {}))
        raise ValueError(f"Unsupported tool: {name}")
