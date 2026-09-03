from __future__ import annotations

from fastapi import HTTPException

from ..audit import AuditStore
from ..graylog import GraylogClient
from ..security import agent_context
from ..settings import Settings


class GraylogService:
    """Registry and use cases for configured Graylog connections."""

    def __init__(self, settings: Settings, audit: AuditStore):
        self.settings = settings
        self.audit = audit
        self.clients: dict[int, GraylogClient] = {}

    async def client(self, server_id: int | None = None) -> GraylogClient:
        context = agent_context.get()
        selected_id = server_id or (context or {}).get("graylog_server_id")
        if not selected_id:
            raise HTTPException(status_code=403, detail="No Graylog server is assigned to this client")
        selected_id = int(selected_id)
        server = await self.audit.get_server(selected_id)
        if not server:
            raise HTTPException(status_code=404, detail="Graylog server not found")
        if selected_id not in self.clients:
            self.clients[selected_id] = GraylogClient(self.settings, self.audit, server=server)
        return self.clients[selected_id]

    async def invalidate(self, server_id: int) -> None:
        stale = self.clients.pop(server_id, None)
        if stale:
            await stale.close()

    async def close(self) -> None:
        for client in self.clients.values():
            await client.close()
        self.clients.clear()

