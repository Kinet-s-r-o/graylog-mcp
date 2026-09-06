from __future__ import annotations

from fastapi import HTTPException
from typing import Any

from ..graylog import GraylogClient
from ..persistence.protocols import GraylogRepository
from ..security import agent_context
from ..settings import Settings


class GraylogService:
    """Registry and use cases for configured Graylog connections."""

    def __init__(self, settings: Settings, audit: GraylogRepository):
        self.settings = settings
        self.audit = audit
        self.registry = GraylogClientRegistry(settings, audit)

    @property
    def clients(self) -> dict[int, GraylogClient]:
        return self.registry.clients

    async def client(self, server_id: int | None = None) -> GraylogClient:
        context = agent_context.get()
        selected_id = server_id or (context or {}).get("graylog_server_id")
        if not selected_id:
            raise HTTPException(status_code=403, detail="No Graylog server is assigned to this client")
        selected_id = int(selected_id)
        return await self.registry.get(selected_id)

    async def invalidate(self, server_id: int) -> None:
        await self.registry.invalidate(server_id)

    async def close(self) -> None:
        await self.registry.close()


class GraylogClientRegistry:
    """Owns cached clients and replaces them when connection configuration changes."""

    def __init__(self, settings: Settings, repository: GraylogRepository):
        self.settings = settings
        self.repository = repository
        self.clients: dict[int, GraylogClient] = {}
        self._fingerprints: dict[int, tuple[Any, ...]] = {}

    @staticmethod
    def _fingerprint(server: dict[str, Any]) -> tuple[Any, ...]:
        return (
            server.get("url"),
            server.get("api_token"),
            bool(server.get("verify_tls", True)),
            float(server.get("timeout_seconds", 30)),
        )

    async def get(self, server_id: int) -> GraylogClient:
        server = await self.repository.get_server(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="Graylog server not found")
        fingerprint = self._fingerprint(server)
        if server_id in self.clients and self._fingerprints.get(server_id) == fingerprint:
            return self.clients[server_id]
        await self.invalidate(server_id)
        self.clients[server_id] = GraylogClient(self.settings, self.repository, server=server)
        self._fingerprints[server_id] = fingerprint
        return self.clients[server_id]

    async def invalidate(self, server_id: int) -> None:
        stale = self.clients.pop(server_id, None)
        self._fingerprints.pop(server_id, None)
        if stale:
            await stale.close()

    async def close(self) -> None:
        clients = tuple(self.clients.values())
        self.clients.clear()
        self._fingerprints.clear()
        for client in clients:
            await client.close()
