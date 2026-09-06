from __future__ import annotations

from typing import Any, Protocol

from ..domain.models import QueryDefinition
from ..graylog import GraylogClient
from ..settings import Settings


class QueryExecutor(Protocol):
    query_type: str

    async def execute(
        self, definition: QueryDefinition, client: GraylogClient, settings: Settings, query_name: str
    ) -> Any: ...


class MessageQueryExecutor:
    query_type = "messages"

    async def execute(self, definition, client, settings, query_name):
        return await client.search_messages(
            definition.query,
            definition.minutes,
            definition.limit or settings.graylog_default_limit,
            definition.fields,
            query_name,
        )


class AggregateQueryExecutor:
    query_type = "aggregate"

    async def execute(self, definition, client, settings, query_name):
        return await client.aggregate(
            definition.query,
            definition.minutes,
            definition.group_by,
            definition.metrics,
            definition.interval,
            query_name,
        )


class QueryExecutorRegistry:
    """Registry for additive query types; routing code need not change."""

    def __init__(self, executors: list[QueryExecutor] | None = None):
        self._executors: dict[str, QueryExecutor] = {}
        for executor in executors or [MessageQueryExecutor(), AggregateQueryExecutor()]:
            self.register(executor)

    def register(self, executor: QueryExecutor) -> None:
        if not executor.query_type:
            raise ValueError("Query executor must declare query_type")
        self._executors[executor.query_type] = executor

    def get(self, query_type: str) -> QueryExecutor:
        try:
            return self._executors[query_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported query type: {query_type}") from exc

    def types(self) -> tuple[str, ...]:
        return tuple(self._executors)
