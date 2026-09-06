from __future__ import annotations

from typing import Any

from .graylog_service import GraylogService
from .query_service import QueryService


class GraylogOperations:
    """Transport-neutral application operations used by REST and MCP adapters."""

    def __init__(self, graylog: GraylogService, queries: QueryService):
        self.graylog = graylog
        self.queries = queries

    async def search_messages(self, **args):
        return await (await self.graylog.client()).search_messages(**args)

    async def aggregate(self, **args):
        return await (await self.graylog.client()).aggregate(**args)

    async def streams(self):
        return await (await self.graylog.client()).streams()

    async def execute_tool(self, name: str, args: dict[str, Any]):
        return await self.queries.execute_tool(name, args)


class MCPToolAdapter:
    """Adapter boundary for MCP protocol functions."""

    def __init__(self, operations: GraylogOperations):
        self.operations = operations

    async def invoke(self, name: str, args: dict[str, Any]):
        return await self.operations.execute_tool(name, args)


class RESTToolAdapter:
    """Adapter boundary for HTTP request models and response serialization."""

    def __init__(self, operations: GraylogOperations):
        self.operations = operations

    async def search_messages(self, **args): return await self.operations.search_messages(**args)
    async def aggregate(self, **args): return await self.operations.aggregate(**args)
    async def streams(self): return await self.operations.streams()
