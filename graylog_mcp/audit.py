from __future__ import annotations

import json
import ipaddress
import logging
import re
import time
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from .security import SecretCipher

log = logging.getLogger(__name__)


class AuditStore:
    """Small, local and bounded audit store for requests and responses."""

    def __init__(self, path: Path, retention_days: int, max_rows: int, max_payload_chars: int,
                 *, secret_encryption_key: str | None = None, redact_fields: set[str] | None = None):
        self.path = path
        self.retention_days = max(1, retention_days)
        self.max_rows = max(100, max_rows)
        self.max_payload_chars = max(1000, max_payload_chars)
        self.secret_cipher = SecretCipher(secret_encryption_key)
        self.redact_fields = {field.lower() for field in (redact_fields or {
            "authorization", "api_key", "api_token", "password", "secret", "token",
        })}
        self.db: aiosqlite.Connection | None = None

    async def open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = await aiosqlite.connect(self.path)
        await self.db.execute("PRAGMA foreign_keys=ON")
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA busy_timeout=5000")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              source TEXT NOT NULL,
              operation TEXT NOT NULL,
              request_json TEXT,
              response_json TEXT,
              status_code INTEGER,
              duration_ms REAL,
              success INTEGER NOT NULL,
              error TEXT,
              agent_id INTEGER
            )
        """)
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC)")
        await self.db.execute("""CREATE TABLE IF NOT EXISTS graylog_servers (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          url TEXT NOT NULL, api_token TEXT NOT NULL, verify_tls INTEGER NOT NULL DEFAULT 1,
          timeout_seconds REAL NOT NULL DEFAULT 30, created_at TEXT NOT NULL
        )""")
        await self.db.execute("""CREATE TABLE IF NOT EXISTS agents (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          api_key_hash TEXT NOT NULL UNIQUE, api_key_last4 TEXT NOT NULL,
          graylog_server_id INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, allowed_ips TEXT NOT NULL DEFAULT '[]',
          FOREIGN KEY(graylog_server_id) REFERENCES graylog_servers(id)
        )""")
        agent_columns = {row[1] for row in await (await self.db.execute("PRAGMA table_info(agents)")).fetchall()}
        if "allowed_ips" not in agent_columns:
            await self.db.execute("ALTER TABLE agents ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT '[]'")
        audit_columns = {row[1] for row in await (await self.db.execute("PRAGMA table_info(audit_log)")).fetchall()}
        if "agent_id" not in audit_columns:
            await self.db.execute("ALTER TABLE audit_log ADD COLUMN agent_id INTEGER")
        await self.db.execute("""CREATE TABLE IF NOT EXISTS query_definitions (
          name TEXT PRIMARY KEY, definition_json TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
        await self.db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS audit_fts USING fts5(
            source, operation, request_json, response_json, error,
            tokenize='unicode61', content='audit_log', content_rowid='id'
        )""")
        await self.db.execute("""CREATE TRIGGER IF NOT EXISTS audit_log_ai AFTER INSERT ON audit_log BEGIN
            INSERT INTO audit_fts(rowid,source,operation,request_json,response_json,error)
            VALUES (new.id,new.source,new.operation,new.request_json,new.response_json,new.error);
        END""")
        await self.db.execute("""CREATE TRIGGER IF NOT EXISTS audit_log_ad AFTER DELETE ON audit_log BEGIN
            INSERT INTO audit_fts(audit_fts,rowid,source,operation,request_json,response_json,error)
            VALUES ('delete',old.id,old.source,old.operation,old.request_json,old.response_json,old.error);
        END""")
        await self.db.execute("""CREATE TRIGGER IF NOT EXISTS audit_log_au AFTER UPDATE ON audit_log BEGIN
            INSERT INTO audit_fts(audit_fts,rowid,source,operation,request_json,response_json,error)
            VALUES ('delete',old.id,old.source,old.operation,old.request_json,old.response_json,old.error);
            INSERT INTO audit_fts(rowid,source,operation,request_json,response_json,error)
            VALUES (new.id,new.source,new.operation,new.request_json,new.response_json,new.error);
        END""")
        audit_count = int((await (await self.db.execute("SELECT COUNT(*) FROM audit_log")).fetchone())[0])
        fts_count = int((await (await self.db.execute("SELECT COUNT(*) FROM audit_fts")).fetchone())[0])
        if audit_count != fts_count:
            await self.db.execute("INSERT INTO audit_fts(audit_fts) VALUES('rebuild')")
        rows = await (await self.db.execute("SELECT id,api_token FROM graylog_servers")).fetchall()
        for server_id, token in rows:
            if token.startswith(self.secret_cipher.prefix):
                self.secret_cipher.decrypt(token)
            elif self.secret_cipher.enabled:
                encrypted = self.secret_cipher.encrypt(token)
                if encrypted != token:
                    await self.db.execute("UPDATE graylog_servers SET api_token=? WHERE id=?", (encrypted, server_id))
        await self.db.commit()
        await self.cleanup()

    def _redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if self._sensitive_key(str(key)) else self._redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact(item) for item in value)
        if isinstance(value, str):
            return self._redact_text(value)
        return value

    def _sensitive_key(self, key: str) -> bool:
        normalized = key.strip().lower().replace("-", "_")
        return any(normalized == field or normalized.endswith(f"_{field}") for field in self.redact_fields)

    def _redact_text(self, value: str) -> str:
        value = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        for field in self.redact_fields:
            spelling = re.escape(field).replace("_", "[-_]")
            value = re.sub(
                rf"(?i)(\b{spelling}\b\s*[:=]\s*)([^\s,;]+)",
                rf"\1[REDACTED]",
                value,
            )
        return value

    def _compact(self, value: Any) -> str:
        try:
            value = json.dumps(self._redact(value), ensure_ascii=False, default=str)
        except Exception:
            value = "[UNSERIALIZABLE AUDIT PAYLOAD]"
        return value[:self.max_payload_chars]

    async def record(self, *, source: str, operation: str, request: Any = None,
                     response: Any = None, status_code: int | None = None,
                     duration_ms: float | None = None, success: bool = True,
                     error: str | None = None, agent_id: int | None = None):
        if not self.db:
            return
        try:
            await self.db.execute(
                "INSERT INTO audit_log(created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error,agent_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), source, operation,
                 self._compact(request) if request is not None else None,
                 self._compact(response) if response is not None else None,
                 status_code, duration_ms, int(success),
                 self._redact_text(error)[:self.max_payload_chars] if error else None, agent_id),
            )
            await self.db.commit()
            await self.cleanup()
        except Exception:
            log.exception("Could not write audit record")

    async def cleanup(self):
        if not self.db:
            return
        await self.db.execute("DELETE FROM audit_log WHERE datetime(created_at) < datetime('now', ?)", (f"-{self.retention_days} days",))
        await self.db.execute("DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)", (self.max_rows,))
        await self.db.commit()

    async def recent(self, limit: int = 100, search: str | None = None, source: str | None = None,
                     offset: int = 0, agent_id: int | None = None):
        if not self.db:
            return []
        limit = min(max(1, limit), 500)
        offset = max(0, offset)
        if search:
            # FTS5 supports phrases, prefixes (term*) and boolean expressions.
            # If a user enters invalid FTS syntax, use a safe substring fallback.
            try:
                sql = "SELECT a.id,a.created_at,a.source,a.operation,a.request_json,a.response_json,a.status_code,a.duration_ms,a.success,a.error FROM audit_log a JOIN audit_fts f ON f.rowid=a.id WHERE audit_fts MATCH ?"
                args: list[Any] = [search]
                if source: sql += " AND a.source = ?"; args.append(source)
                if agent_id is not None: sql += " AND a.agent_id = ?"; args.append(agent_id)
                sql += " ORDER BY a.id DESC LIMIT ? OFFSET ?"; args.extend([limit, offset])
                cursor = await self.db.execute(sql, args)
            except Exception:
                sql = "SELECT id,created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error FROM audit_log WHERE (request_json LIKE ? OR response_json LIKE ? OR operation LIKE ? OR error LIKE ?)"
                needle = f"%{search}%"; args = [needle] * 4
                if source: sql += " AND source = ?"; args.append(source)
                if agent_id is not None: sql += " AND agent_id = ?"; args.append(agent_id)
                sql += " ORDER BY id DESC LIMIT ? OFFSET ?"; args.extend([limit, offset])
                cursor = await self.db.execute(sql, args)
        else:
            sql = "SELECT id,created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error FROM audit_log"
            args = []
            conditions = []
            if source: conditions.append("source = ?"); args.append(source)
            if agent_id is not None: conditions.append("agent_id = ?"); args.append(agent_id)
            if conditions: sql += " WHERE " + " AND ".join(conditions)
            sql += " ORDER BY id DESC LIMIT ? OFFSET ?"; args.extend([limit, offset])
            cursor = await self.db.execute(sql, args)
        rows = await cursor.fetchall()
        columns = ["id", "created_at", "source", "operation", "request_json", "response_json", "status_code", "duration_ms", "success", "error"]
        return [dict(zip(columns, row)) for row in rows]

    async def count_recent(self, search: str | None = None, source: str | None = None,
                           agent_id: int | None = None):
        if not self.db:
            return 0
        if search:
            try:
                sql = "SELECT COUNT(*) FROM audit_log a JOIN audit_fts f ON f.rowid=a.id WHERE audit_fts MATCH ?"
                args: list[Any] = [search]
                if source: sql += " AND a.source = ?"; args.append(source)
                if agent_id is not None: sql += " AND a.agent_id = ?"; args.append(agent_id)
                cursor = await self.db.execute(sql, args)
            except Exception:
                sql = "SELECT COUNT(*) FROM audit_log WHERE (request_json LIKE ? OR response_json LIKE ? OR operation LIKE ? OR error LIKE ?)"
                needle = f"%{search}%"; args = [needle] * 4
                if source: sql += " AND source = ?"; args.append(source)
                if agent_id is not None: sql += " AND agent_id = ?"; args.append(agent_id)
                cursor = await self.db.execute(sql, args)
        else:
            sql = "SELECT COUNT(*) FROM audit_log"
            args = []
            conditions = []
            if source: conditions.append("source = ?"); args.append(source)
            if agent_id is not None: conditions.append("agent_id = ?"); args.append(agent_id)
            if conditions: sql += " WHERE " + " AND ".join(conditions)
            cursor = await self.db.execute(sql, args)
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def close(self):
        if self.db:
            await self.db.close()
            self.db = None

    async def list_servers(self):
        cursor = await self.db.execute("SELECT id,name,url,verify_tls,timeout_seconds,created_at FROM graylog_servers ORDER BY name")
        rows = await cursor.fetchall()
        return [dict(zip(["id","name","url","verify_tls","timeout_seconds","created_at"], row)) for row in rows]

    async def add_server(self, name: str, url: str, api_token: str, verify_tls: bool = True, timeout_seconds: float = 30):
        await self.db.execute("INSERT INTO graylog_servers(name,url,api_token,verify_tls,timeout_seconds,created_at) VALUES(?,?,?,?,?,?)",
                              (name, url.rstrip("/"), self.secret_cipher.encrypt(api_token), int(verify_tls), timeout_seconds, datetime.now(timezone.utc).isoformat()))
        await self.db.commit()
        cursor = await self.db.execute("SELECT id,name,url,verify_tls,timeout_seconds,created_at FROM graylog_servers WHERE name=?", (name,))
        row = await cursor.fetchone()
        return dict(zip(["id","name","url","verify_tls","timeout_seconds","created_at"], row))

    async def update_server(self, server_id: int, name: str, url: str, api_token: str | None = None,
                            verify_tls: bool = True, timeout_seconds: float = 30):
        existing = await self.get_server(server_id)
        if not existing:
            raise ValueError("Graylog server not found")
        token = self.secret_cipher.encrypt(api_token or existing["api_token"])
        await self.db.execute(
            "UPDATE graylog_servers SET name=?,url=?,api_token=?,verify_tls=?,timeout_seconds=? WHERE id=?",
            (name, url.rstrip("/"), token, int(verify_tls), timeout_seconds, server_id),
        )
        await self.db.commit()
        cursor = await self.db.execute(
            "SELECT id,name,url,verify_tls,timeout_seconds,created_at FROM graylog_servers WHERE id=?", (server_id,)
        )
        row = await cursor.fetchone()
        return dict(zip(["id","name","url","verify_tls","timeout_seconds","created_at"], row))

    async def remove_server(self, server_id: int):
        cursor = await self.db.execute("SELECT COUNT(*) FROM agents WHERE graylog_server_id=?", (server_id,))
        linked = int((await cursor.fetchone())[0])
        if linked:
            raise ValueError("Cannot delete a Graylog server while MCP clients are assigned to it")
        await self.db.execute("DELETE FROM graylog_servers WHERE id=?", (server_id,)); await self.db.commit()

    @staticmethod
    def normalize_allowed_ips(value: str | list[str] | None) -> list[str]:
        if value is None: return []
        entries = re.split(r"[\s,]+", value) if isinstance(value, str) else value
        result = []
        for entry in entries:
            entry = str(entry).strip()
            if not entry: continue
            try: result.append(str(ipaddress.ip_network(entry, strict=False)))
            except ValueError as exc: raise ValueError(f"Invalid CIDR address: {entry}") from exc
        return list(dict.fromkeys(result))

    @staticmethod
    def decode_allowed_ips(raw: str | None) -> list[str]:
        try: return json.loads(raw or "[]")
        except (TypeError, json.JSONDecodeError): return []

    async def list_agents(self):
        cursor = await self.db.execute("""SELECT a.id,a.name,a.api_key_last4,a.graylog_server_id,a.active,a.created_at,a.allowed_ips,s.name
            FROM agents a JOIN graylog_servers s ON s.id=a.graylog_server_id ORDER BY a.name""")
        rows = await cursor.fetchall()
        cols = ["id","name","api_key_last4","graylog_server_id","active","created_at","allowed_ips","graylog_server_name"]
        result = []
        for row in rows:
            item = dict(zip(cols, row)); item["allowed_ips"] = self.decode_allowed_ips(item["allowed_ips"]); result.append(item)
        return result

    async def add_agent(self, name: str, server_id: int, api_key: str | None = None, allowed_ips: str | list[str] | None = None):
        api_key = api_key or "glmc_" + secrets.token_urlsafe(32)
        if len(api_key) < 24:
            raise ValueError("MCP API key must contain at least 24 characters")
        normalized_ips = self.normalize_allowed_ips(allowed_ips)
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        await self.db.execute("INSERT INTO agents(name,api_key_hash,api_key_last4,graylog_server_id,created_at,allowed_ips) VALUES(?,?,?,?,?,?)",
                              (name, digest, api_key[-4:], server_id, datetime.now(timezone.utc).isoformat(), json.dumps(normalized_ips)))
        await self.db.commit()
        return {"api_key": api_key, "name": name, "graylog_server_id": server_id, "allowed_ips": normalized_ips}

    async def remove_agent(self, agent_id: int):
        await self.db.execute("DELETE FROM agents WHERE id=?", (agent_id,)); await self.db.commit()

    async def update_agent(self, agent_id: int, name: str, server_id: int, active: bool = True,
                           api_key: str | None = None, allowed_ips: str | list[str] | None = None):
        cursor = await self.db.execute("SELECT id FROM agents WHERE id=?", (agent_id,))
        if not await cursor.fetchone():
            raise ValueError("MCP client not found")
        normalized_ips = self.normalize_allowed_ips(allowed_ips) if allowed_ips is not None else None
        if api_key:
            if len(api_key) < 24:
                raise ValueError("MCP API key must contain at least 24 characters")
            digest = hashlib.sha256(api_key.encode()).hexdigest()
            await self.db.execute(
                "UPDATE agents SET name=?,api_key_hash=?,api_key_last4=?,graylog_server_id=?,active=?,allowed_ips=COALESCE(?,allowed_ips) WHERE id=?",
                (name, digest, api_key[-4:], server_id, int(active), json.dumps(normalized_ips) if normalized_ips is not None else None, agent_id),
            )
        else:
            await self.db.execute(
                "UPDATE agents SET name=?,graylog_server_id=?,active=?,allowed_ips=COALESCE(?,allowed_ips) WHERE id=?",
                (name, server_id, int(active), json.dumps(normalized_ips) if normalized_ips is not None else None, agent_id),
            )
        await self.db.commit()
        items = await self.list_agents()
        result = next(item for item in items if item["id"] == agent_id)
        if api_key:
            result["api_key"] = api_key
        return result

    async def authenticate_agent(self, api_key: str):
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        cursor = await self.db.execute("""SELECT a.id,a.name,a.graylog_server_id,s.name,s.url,s.api_token,s.verify_tls,s.timeout_seconds,a.allowed_ips
            FROM agents a JOIN graylog_servers s ON s.id=a.graylog_server_id
            WHERE a.api_key_hash=? AND a.active=1""", (digest,))
        row = await cursor.fetchone()
        if not row: return None
        result = dict(zip(["agent_id","agent_name","graylog_server_id","server_name","url","api_token","verify_tls","timeout_seconds","allowed_ips"], row))
        result["api_token"] = self.secret_cipher.decrypt(result["api_token"])
        result["allowed_ips"] = self.decode_allowed_ips(result["allowed_ips"])
        return result

    async def get_server(self, server_id: int):
        cursor = await self.db.execute("SELECT id,name,url,api_token,verify_tls,timeout_seconds FROM graylog_servers WHERE id=?", (server_id,))
        row = await cursor.fetchone()
        if not row: return None
        result = dict(zip(["id","name","url","api_token","verify_tls","timeout_seconds"], row))
        result["api_token"] = self.secret_cipher.decrypt(result["api_token"])
        return result

    async def seed_queries(self, definitions: dict[str, dict]):
        now = datetime.now(timezone.utc).isoformat()
        for name, definition in definitions.items():
            await self.db.execute(
                "INSERT OR IGNORE INTO query_definitions(name,definition_json,created_at,updated_at) VALUES(?,?,?,?)",
                (name, json.dumps(definition, ensure_ascii=False), now, now),
            )
        await self.db.commit()

    async def list_queries(self):
        cursor = await self.db.execute("SELECT name,definition_json,created_at,updated_at FROM query_definitions ORDER BY name")
        rows = await cursor.fetchall()
        result = []
        for name, raw, created_at, updated_at in rows:
            item = json.loads(raw); item.update({"name": name, "created_at": created_at, "updated_at": updated_at})
            result.append(item)
        return result

    async def get_query(self, name: str):
        cursor = await self.db.execute("SELECT definition_json FROM query_definitions WHERE name=?", (name,))
        row = await cursor.fetchone()
        return json.loads(row[0]) if row else None

    async def save_query(self, name: str, definition: dict):
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute("""INSERT INTO query_definitions(name,definition_json,created_at,updated_at)
            VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET definition_json=excluded.definition_json,updated_at=excluded.updated_at""",
            (name, json.dumps(definition, ensure_ascii=False), now, now),
        )
        await self.db.commit()
        return {"name": name, **definition, "updated_at": now}

    async def remove_query(self, name: str):
        await self.db.execute("DELETE FROM query_definitions WHERE name=?", (name,)); await self.db.commit()


def stopwatch() -> float:
    return time.perf_counter()
