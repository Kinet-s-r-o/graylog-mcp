from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite


SCHEMA_VERSION = 3


async def _columns(db: aiosqlite.Connection, table: str) -> set[str]:
    return {row[1] for row in await (await db.execute(f"PRAGMA table_info({table})")).fetchall()}


async def run_migrations(db: aiosqlite.Connection) -> None:
    """Apply repeatable, additive migrations to both new and legacy databases."""

    await db.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
        )"""
    )
    await db.execute(
        """CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at TEXT NOT NULL, source TEXT NOT NULL, operation TEXT NOT NULL,
          request_json TEXT, response_json TEXT, status_code INTEGER,
          duration_ms REAL, success INTEGER NOT NULL, error TEXT, agent_id INTEGER
        )"""
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC)")
    await db.execute(
        """CREATE TABLE IF NOT EXISTS graylog_servers (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          url TEXT NOT NULL, api_token TEXT NOT NULL, verify_tls INTEGER NOT NULL DEFAULT 1,
          timeout_seconds REAL NOT NULL DEFAULT 30, created_at TEXT NOT NULL
        )"""
    )
    await db.execute(
        """CREATE TABLE IF NOT EXISTS agents (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          api_key_hash TEXT NOT NULL UNIQUE, api_key_last4 TEXT NOT NULL,
          graylog_server_id INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, allowed_ips TEXT NOT NULL DEFAULT '[]',
          FOREIGN KEY(graylog_server_id) REFERENCES graylog_servers(id)
        )"""
    )
    if "allowed_ips" not in await _columns(db, "agents"):
        await db.execute("ALTER TABLE agents ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT '[]'")
    if "agent_id" not in await _columns(db, "audit_log"):
        await db.execute("ALTER TABLE audit_log ADD COLUMN agent_id INTEGER")
    if "client_ip" not in await _columns(db, "audit_log"):
        await db.execute("ALTER TABLE audit_log ADD COLUMN client_ip TEXT")
    await db.execute(
        """CREATE TABLE IF NOT EXISTS query_definitions (
          name TEXT PRIMARY KEY, definition_json TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )"""
    )
    await db.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS audit_fts USING fts5(
        source, operation, request_json, response_json, error,
        tokenize='unicode61', content='audit_log', content_rowid='id'
        )"""
    )
    await db.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_log_ai AFTER INSERT ON audit_log BEGIN
        INSERT INTO audit_fts(rowid,source,operation,request_json,response_json,error)
        VALUES (new.id,new.source,new.operation,new.request_json,new.response_json,new.error);
        END"""
    )
    await db.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_log_ad AFTER DELETE ON audit_log BEGIN
        INSERT INTO audit_fts(audit_fts,rowid,source,operation,request_json,response_json,error)
        VALUES ('delete',old.id,old.source,old.operation,old.request_json,old.response_json,old.error);
        END"""
    )
    await db.execute(
        """CREATE TRIGGER IF NOT EXISTS audit_log_au AFTER UPDATE ON audit_log BEGIN
        INSERT INTO audit_fts(audit_fts,rowid,source,operation,request_json,response_json,error)
        VALUES ('delete',old.id,old.source,old.operation,old.request_json,old.response_json,old.error);
        INSERT INTO audit_fts(rowid,source,operation,request_json,response_json,error)
        VALUES (new.id,new.source,new.operation,new.request_json,new.response_json,new.error);
        END"""
    )
    audit_count = int((await (await db.execute("SELECT COUNT(*) FROM audit_log")).fetchone())[0])
    fts_count = int((await (await db.execute("SELECT COUNT(*) FROM audit_fts")).fetchone())[0])
    if audit_count != fts_count:
        await db.execute("INSERT INTO audit_fts(audit_fts) VALUES('rebuild')")
    now = datetime.now(timezone.utc).isoformat()
    for version in range(1, SCHEMA_VERSION + 1):
        await db.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(?,?)",
            (version, now),
        )
    await db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    await db.commit()
