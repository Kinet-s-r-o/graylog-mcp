from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from ..audit import AuditStore
from ..security import agent_context, ip_allowed, resolve_client_ip


bearer = HTTPBearer(auto_error=False)


@dataclass(slots=True)
class AgentAuth:
    audit: AuditStore
    trusted_proxy_networks: tuple

    def client_ip(self, request: Request) -> str:
        peer_ip = request.client.host if request.client else ""
        return resolve_client_ip(
            peer_ip,
            request.headers.get("x-forwarded-for"),
            self.trusted_proxy_networks,
        )

    async def authenticate_key(self, request: Request, api_key: str | None):
        context = await self.audit.authenticate_agent(api_key or "") if api_key else None
        if not context:
            raise HTTPException(status_code=401, detail="Invalid or inactive agent API key")
        client_ip = self.client_ip(request)
        if not ip_allowed(client_ip, context.get("allowed_ips", [])):
            raise HTTPException(status_code=403, detail="Agent IP address is not allowed")
        context["client_ip"] = client_ip
        return context

    async def require(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ):
        if not credentials:
            raise HTTPException(status_code=401, detail="Bearer API key required")
        context = await self.authenticate_key(request, credentials.credentials)
        token = agent_context.set(context)
        try:
            yield context
        finally:
            agent_context.reset(token)
