from __future__ import annotations

from pathlib import Path

import aiosqlite


class Database:
    """Owns the SQLite connection and its process-wide safety pragmas."""

    def __init__(self, path: Path, *, busy_timeout_ms: int = 5000):
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        self.connection: aiosqlite.Connection | None = None

    async def open(self) -> aiosqlite.Connection:
        if self.connection is not None:
            return self.connection
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = await aiosqlite.connect(self.path)
        await connection.execute("PRAGMA foreign_keys=ON")
        await connection.execute("PRAGMA journal_mode=WAL")
        await connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        self.connection = connection
        return connection

    async def close(self) -> None:
        if self.connection is not None:
            await self.connection.close()
            self.connection = None

