from __future__ import annotations

from typing import Any

from ..graylog import GraylogClient
from ..persistence.protocols import ManagementRepository
from .graylog_service import GraylogService
from .query_service import QueryService


class AdminService:
    """Administrative use cases shared by the WebUI adapter and future APIs."""

    def __init__(self, repository: Any, graylog: GraylogService, queries: QueryService):
        self.repository: ManagementRepository = repository
        self.graylog = graylog
        self.queries = queries

    async def list_servers(self): return await self.repository.list_servers()
    async def add_server(self, **values): return await self.repository.add_server(**values)

    async def update_server(self, server_id: int, **values):
        result = await self.repository.update_server(server_id, **values)
        await self.graylog.invalidate(server_id)
        return result

    async def delete_server(self, server_id: int):
        await self.repository.remove_server(server_id)
        await self.graylog.invalidate(server_id)

    async def get_server(self, server_id: int): return await self.repository.get_server(server_id)
    async def list_agents(self): return await self.repository.list_agents()
    async def add_agent(self, **values): return await self.repository.add_agent(**values)
    async def update_agent(self, agent_id: int, **values): return await self.repository.update_agent(agent_id, **values)
    async def delete_agent(self, agent_id: int): return await self.repository.remove_agent(agent_id)

    async def test_server(self, server: dict[str, Any]):
        client = GraylogClient(self.graylog.settings, self.repository, server=server)
        try:
            return await client.request("GET", "/api/cluster")
        finally:
            await client.close()

    async def execute_query(self, body):
        client = await self.graylog.client(body.server_id)
        if body.group_by is not None:
            return await client.aggregate(
                body.query, body.minutes, body.group_by, body.metrics, body.interval
            )
        return await client.search_messages(body.query, body.minutes, body.limit)

    async def streams(self, server_id: int):
        return await (await self.graylog.client(server_id)).streams()

    async def audit(self, *args, **kwargs):
        return await self.repository.recent(*args, **kwargs)

    async def audit_count(self, *args, **kwargs):
        return await self.repository.count_recent(*args, **kwargs)
