"""SessionStore — cache-plus-persistence store for EngagementSession.

In-memory dict is the hot path (identity preserved for a resident session,
per RESEARCH.md Pitfall 3). SQLite + WAL (matching backend/memory/client_profile.py
and backend/intelligence/research_kb.py) is the restart-recovery layer:
resolve() checks memory first, falls back to a disk read only on a cache miss.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from backend.session.engagement_session import EngagementSession


class SessionStore:
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._sessions: Dict[str, EngagementSession] = {}
        self._db_path = db_path or Path("data/sessions/sessions.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Open the SQLite connection and create the sessions table if needed."""
        if self._conn is not None:
            return
        async with self._lock:
            if self._conn is not None:
                return
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = await asyncio.to_thread(
                sqlite3.connect, str(self._db_path), check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
            # NOTE: journal_mode persists in the DB file; synchronous does NOT —
            # must be reissued on every new connection (see RESEARCH.md Pitfall 4).
            await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")
            await asyncio.to_thread(
                self._conn.executescript,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id  TEXT PRIMARY KEY,
                    payload     TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );
                """,
            )
            await asyncio.to_thread(self._conn.commit)

    async def close(self) -> None:
        if self._conn is not None:
            await asyncio.to_thread(self._conn.close)
            self._conn = None

    async def create(self, engagement_id: Optional[str] = None) -> EngagementSession:
        if self._conn is None:
            await self.initialize()
        session = EngagementSession.create(engagement_id=engagement_id)
        self._sessions[session.session_id] = session
        await self.save(session)
        return session

    async def resolve(self, session_id: str) -> Optional[EngagementSession]:
        if session_id in self._sessions:
            # Hot path — same object identity preserved (RESEARCH.md Pitfall 3).
            return self._sessions[session_id]

        if self._conn is None:
            await self.initialize()

        row = await asyncio.to_thread(
            lambda: self._conn.execute(
                "SELECT payload FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        )
        if row is None:
            return None

        session = EngagementSession.from_row(row["payload"])
        self._sessions[session_id] = session  # repopulate the cache
        return session

    async def touch(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session is None:
            session = await self.resolve(session_id)
        if session is None:
            return
        session.last_active = datetime.utcnow()
        await self.save(session)

    async def save(self, session: EngagementSession) -> None:
        if self._conn is None:
            await self.initialize()
        await asyncio.to_thread(
            self._conn.execute,
            """
            INSERT INTO sessions (session_id, payload, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (session.session_id, session.to_row(), datetime.utcnow().isoformat()),
        )
        await asyncio.to_thread(self._conn.commit)


session_store = SessionStore()
