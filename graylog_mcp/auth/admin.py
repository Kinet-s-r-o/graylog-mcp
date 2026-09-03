from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import HTTPException
from starlette.requests import Request

from ..security import LoginThrottle, SessionStore, resolve_client_ip
from ..settings import Settings


SESSION_COOKIE = "graylog_ui_session"


@dataclass(slots=True)
class AdminAuth:
    settings: Settings
    sessions: SessionStore
    throttle: LoginThrottle
    trusted_proxy_networks: tuple

    def client_ip(self, request: Request) -> str:
        peer_ip = request.client.host if request.client else ""
        return resolve_client_ip(
            peer_ip,
            request.headers.get("x-forwarded-for"),
            self.trusted_proxy_networks,
        )

    def session(self, request: Request):
        return self.sessions.get(request.cookies.get(SESSION_COOKIE))

    async def require(self, request: Request):
        session = self.session(request)
        if session is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return session

    def valid_csrf(self, request: Request) -> bool:
        return self.sessions.valid_csrf(
            request.cookies.get(SESSION_COOKIE), request.headers.get("x-csrf-token")
        )

    def credentials_valid(self, username: str, password: str) -> bool:
        expected = self.settings.ui_password.get_secret_value()
        return hmac.compare_digest(username, self.settings.ui_username) and hmac.compare_digest(
            password, expected
        )


def create_admin_auth(settings: Settings, trusted_proxy_networks: tuple) -> AdminAuth:
    return AdminAuth(
        settings=settings,
        sessions=SessionStore(settings.ui_session_ttl_seconds, settings.ui_max_sessions),
        throttle=LoginThrottle(
            settings.ui_login_max_attempts,
            settings.ui_login_window_seconds,
            settings.ui_login_max_clients,
        ),
        trusted_proxy_networks=trusted_proxy_networks,
    )

