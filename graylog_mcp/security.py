from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
import time
from collections import OrderedDict, deque
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterable

from cryptography.fernet import Fernet, InvalidToken


agent_context: ContextVar[dict | None] = ContextVar("agent_context", default=None)


@dataclass(frozen=True)
class WebSession:
    expires_at: float
    csrf_token: str


class SessionStore:
    """Bounded in-process WebUI sessions with deterministic expiry cleanup."""

    def __init__(self, ttl_seconds: int, max_sessions: int):
        self.ttl_seconds = max(60, int(ttl_seconds))
        self.max_sessions = max(1, int(max_sessions))
        self._sessions: OrderedDict[str, WebSession] = OrderedDict()

    def _purge(self, now: float) -> None:
        expired = [token for token, session in self._sessions.items() if session.expires_at <= now]
        for token in expired:
            self._sessions.pop(token, None)

    def create(self, now: float | None = None) -> tuple[str, WebSession]:
        current = time.time() if now is None else now
        self._purge(current)
        while len(self._sessions) >= self.max_sessions:
            self._sessions.popitem(last=False)
        token = secrets.token_urlsafe(32)
        session = WebSession(
            expires_at=current + self.ttl_seconds,
            csrf_token=secrets.token_urlsafe(32),
        )
        self._sessions[token] = session
        return token, session

    def get(self, token: str | None, now: float | None = None) -> WebSession | None:
        if not token:
            return None
        current = time.time() if now is None else now
        self._purge(current)
        session = self._sessions.get(token)
        if session:
            self._sessions.move_to_end(token)
        return session

    def revoke(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def valid_csrf(self, token: str | None, supplied: str | None) -> bool:
        session = self.get(token)
        return bool(session and supplied and secrets.compare_digest(session.csrf_token, supplied))

    def __len__(self) -> int:
        self._purge(time.time())
        return len(self._sessions)


class LoginThrottle:
    """Small per-client sliding-window limiter for failed WebUI logins."""

    def __init__(self, max_attempts: int, window_seconds: int, max_clients: int = 10_000):
        self.max_attempts = max(1, int(max_attempts))
        self.window_seconds = max(1, int(window_seconds))
        self.max_clients = max(1, int(max_clients))
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def _recent(self, key: str, now: float) -> deque[float]:
        attempts = self._failures.get(key, deque())
        cutoff = now - self.window_seconds
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if not attempts:
            self._failures.pop(key, None)
            return deque()
        self._failures.move_to_end(key)
        return attempts

    def allowed(self, key: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        return len(self._recent(key, current)) < self.max_attempts

    def register_failure(self, key: str, now: float | None = None) -> None:
        current = time.time() if now is None else now
        attempts = self._recent(key, current)
        if key not in self._failures:
            while len(self._failures) >= self.max_clients:
                self._failures.popitem(last=False)
            self._failures[key] = attempts
        attempts.append(current)
        self._failures.move_to_end(key)

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)

    def __len__(self) -> int:
        return len(self._failures)


class SecretCipher:
    """Optional authenticated encryption for secrets persisted in SQLite."""

    prefix = "enc:v1:"

    def __init__(self, master_key: str | None):
        self._fernet: Fernet | None = None
        if master_key:
            derived = base64.urlsafe_b64encode(hashlib.sha256(master_key.encode("utf-8")).digest())
            self._fernet = Fernet(derived)

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, value: str) -> str:
        if value.startswith(self.prefix):
            return value
        if not self._fernet:
            return value
        return self.prefix + self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        if not value.startswith(self.prefix):
            return value
        if not self._fernet:
            raise RuntimeError("SECRET_ENCRYPTION_KEY is required to decrypt stored Graylog tokens")
        try:
            return self._fernet.decrypt(value[len(self.prefix):].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Stored Graylog token cannot be decrypted with SECRET_ENCRYPTION_KEY") from exc


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(values: str | Iterable[str] | None) -> tuple[Network, ...]:
    if not values:
        return ()
    entries = values.replace(",", " ").split() if isinstance(values, str) else values
    return tuple(ipaddress.ip_network(str(value).strip(), strict=False) for value in entries if str(value).strip())


def resolve_client_ip(peer_ip: str, forwarded_for: str | None, trusted_proxies: tuple[Network, ...]) -> str:
    """Honor X-Forwarded-For only when the immediate peer is explicitly trusted."""

    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return peer_ip
    if not forwarded_for or not any(peer in network for network in trusted_proxies):
        return peer_ip
    candidates = [item.strip() for item in forwarded_for.split(",") if item.strip()]
    for candidate in reversed(candidates):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not any(address in network for network in trusted_proxies):
            return str(address)
    return peer_ip


def ip_allowed(remote_ip: str, allowed_networks: Iterable[str]) -> bool:
    """Return whether an address is allowed by an empty-or-matching CIDR list."""

    networks = tuple(allowed_networks)
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(remote_ip)
        return any(address in ipaddress.ip_network(network, strict=False) for network in networks)
    except ValueError:
        return False
