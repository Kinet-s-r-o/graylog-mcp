from __future__ import annotations

import string
from typing import Any

from ..persistence.protocols import QueryRepository
from ..domain.models import QueryDefinition
from ..settings import Settings
from .graylog_service import GraylogService
from .query_executors import QueryExecutorRegistry


class QueryService:
    """Renders and executes saved query definitions for every adapter."""

    def __init__(self, settings: Settings, audit: QueryRepository, graylog: Any,
                 executors: QueryExecutorRegistry | None = None):
        self.settings = settings
        self.audit = audit
        self.graylog = graylog
        self.executors = executors or QueryExecutorRegistry()

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

    async def definitions(self):
        return await self.audit.list_queries()

    async def save_definition(self, definition: QueryDefinition | dict[str, Any]):
        if hasattr(definition, "model_dump"):
            definition = definition.model_dump()
        if not isinstance(definition, QueryDefinition):
            definition = QueryDefinition.model_validate(definition)
        return await self.audit.save_query(definition.name, definition.to_storage())

    async def delete_definition(self, name: str):
        return await self.audit.remove_query(name)

    async def audit_recent(self, *args, **kwargs):
        return await self.audit.recent(*args, **kwargs)

    async def audit_count(self, *args, **kwargs):
        return await self.audit.count_recent(*args, **kwargs)

    async def execute_saved(
        self, name: str, parameters: dict[str, Any], server_id: int | None = None
    ):
        query = QueryDefinition.from_storage(name, await self.render(name, parameters))
        client = await self.graylog.client(server_id)
        executor = self.executors.get(query.type)
        return await executor.execute(query, client, self.settings, name)

    async def execute_tool(self, name: str, args: dict[str, Any]):
        client = await self.graylog.client()
        if name == "search_messages":
            return await client.search_messages(**args)
        if name == "aggregate":
            return await client.aggregate(**args)
        if name == "list_streams":
            return await client.streams()
        if name == "list_saved_queries":
            return {"queries": await self.summaries()}
        if name == "run_saved_query":
            return await self.execute_saved(args["name"], args.get("parameters", {}))
        raise ValueError(f"Unsupported tool: {name}")
