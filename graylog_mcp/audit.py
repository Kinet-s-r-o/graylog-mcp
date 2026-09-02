from __future__ import annotations

import json
import logging
import time
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

log = logging.getLogger(__name__)


class AuditStore:
    """Small, local and bounded audit store for requests and responses."""

    def __init__(self, path: Path, retention_days: int, max_rows: int, max_payload_chars: int):
        self.path = path
        self.retention_days = max(1, retention_days)
        self.max_rows = max(100, max_rows)
        self.max_payload_chars = max(1000, max_payload_chars)
        self.db: aiosqlite.Connection | None = None

    async def open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = await aiosqlite.connect(self.path)
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
              error TEXT
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
          created_at TEXT NOT NULL, FOREIGN KEY(graylog_server_id) REFERENCES graylog_servers(id)
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
        await self.db.commit()
        await self.cleanup()

    def _compact(self, value: Any) -> str:
        try:
            value = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            value = str(value)
        return value[:self.max_payload_chars]

    async def record(self, *, source: str, operation: str, request: Any = None,
                     response: Any = None, status_code: int | None = None,
                     duration_ms: float | None = None, success: bool = True,
                     error: str | None = None):
        if not self.db:
            return
        try:
            await self.db.execute(
                "INSERT INTO audit_log(created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error) VALUES(?,?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), source, operation,
                 self._compact(request) if request is not None else None,
                 self._compact(response) if response is not None else None,
                 status_code, duration_ms, int(success), error[:self.max_payload_chars] if error else None),
            )
            await self.db.commit()
            await self.cleanup()
        except Exception:
            log.exception("Could not write audit record")

    async def cleanup(self):
        if not self.db:
            return
        await self.db.execute("DELETE FROM audit_log WHERE created_at < datetime('now', ?)", (f"-{self.retention_days} days",))
        await self.db.execute("DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)", (self.max_rows,))
        await self.db.commit()

    async def recent(self, limit: int = 100, search: str | None = None, source: str | None = None):
        if not self.db:
            return []
        limit = min(max(1, limit), 500)
        if search:
            # FTS5 supports phrases, prefixes (term*) and boolean expressions.
            # If a user enters invalid FTS syntax, use a safe substring fallback.
            try:
                sql = "SELECT a.id,a.created_at,a.source,a.operation,a.request_json,a.response_json,a.status_code,a.duration_ms,a.success,a.error FROM audit_log a JOIN audit_fts f ON f.rowid=a.id WHERE audit_fts MATCH ?"
                args: list[Any] = [search]
                if source: sql += " AND a.source = ?"; args.append(source)
                sql += " ORDER BY a.id DESC LIMIT ?"; args.append(limit)
                cursor = await self.db.execute(sql, args)
            except Exception:
                sql = "SELECT id,created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error FROM audit_log WHERE (request_json LIKE ? OR response_json LIKE ? OR operation LIKE ? OR error LIKE ?)"
                needle = f"%{search}%"; args = [needle] * 4
                if source: sql += " AND source = ?"; args.append(source)
                sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
                cursor = await self.db.execute(sql, args)
        else:
            sql = "SELECT id,created_at,source,operation,request_json,response_json,status_code,duration_ms,success,error FROM audit_log"
            args = []
            if source: sql += " WHERE source = ?"; args.append(source)
            sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
            cursor = await self.db.execute(sql, args)
        rows = await cursor.fetchall()
        columns = ["id", "created_at", "source", "operation", "request_json", "response_json", "status_code", "duration_ms", "success", "error"]
        return [dict(zip(columns, row)) for row in rows]

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
                              (name, url.rstrip("/"), api_token, int(verify_tls), timeout_seconds, datetime.now(timezone.utc).isoformat()))
        await self.db.commit()
        cursor = await self.db.execute("SELECT id,name,url,verify_tls,timeout_seconds,created_at FROM graylog_servers WHERE name=?", (name,))
        row = await cursor.fetchone()
        return dict(zip(["id","name","url","verify_tls","timeout_seconds","created_at"], row))

    async def remove_server(self, server_id: int):
        await self.db.execute("DELETE FROM graylog_servers WHERE id=?", (server_id,)); await self.db.commit()

    async def list_agents(self):
        cursor = await self.db.execute("""SELECT a.id,a.name,a.api_key_last4,a.graylog_server_id,a.active,a.created_at,s.name
            FROM agents a JOIN graylog_servers s ON s.id=a.graylog_server_id ORDER BY a.name""")
        rows = await cursor.fetchall()
        cols = ["id","name","api_key_last4","graylog_server_id","active","created_at","graylog_server_name"]
        return [dict(zip(cols, row)) for row in rows]

    async def add_agent(self, name: str, server_id: int, api_key: str | None = None):
        api_key = api_key or "glmc_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        await self.db.execute("INSERT INTO agents(name,api_key_hash,api_key_last4,graylog_server_id,created_at) VALUES(?,?,?,?,?)",
                              (name, digest, api_key[-4:], server_id, datetime.now(timezone.utc).isoformat()))
        await self.db.commit()
        return {"api_key": api_key, "name": name, "graylog_server_id": server_id}

    async def remove_agent(self, agent_id: int):
        await self.db.execute("DELETE FROM agents WHERE id=?", (agent_id,)); await self.db.commit()

    async def authenticate_agent(self, api_key: str):
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        cursor = await self.db.execute("""SELECT a.id,a.name,a.graylog_server_id,s.name,s.url,s.api_token,s.verify_tls,s.timeout_seconds
            FROM agents a JOIN graylog_servers s ON s.id=a.graylog_server_id
            WHERE a.api_key_hash=? AND a.active=1""", (digest,))
        row = await cursor.fetchone()
        if not row: return None
        return dict(zip(["agent_id","agent_name","graylog_server_id","server_name","url","api_token","verify_tls","timeout_seconds"], row))

    async def get_server(self, server_id: int):
        cursor = await self.db.execute("SELECT id,name,url,api_token,verify_tls,timeout_seconds FROM graylog_servers WHERE id=?", (server_id,))
        row = await cursor.fetchone()
        if not row: return None
        return dict(zip(["id","name","url","api_token","verify_tls","timeout_seconds"], row))


def stopwatch() -> float:
    return time.perf_counter()
