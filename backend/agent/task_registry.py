"""TaskRegistry — directive-level handoff state store (D-10).

Persists directive dispatch state (created/running/completed/failed) to a
`task_registry` table on SessionStore's SHARED SQLite connection
(03-RESEARCH.md Pattern 2) — not a second `sqlite3.connect()`, not a
separate `.db` file. Sharing one connection/database with SessionStore is
what makes "TaskRegistry disagrees with phase_status after a crash"
structurally impossible rather than merely unlikely (WAL mode only
guarantees per-statement atomicity within a single connection, not across
two separate database files).

This lets OmO detect a directive that was dispatched but never reported a
terminal status after a crash mid-directive — PERSIST-01's "resumed session
state must be trustworthy" requirement.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class TaskRegistry:
    """Directive handoff state store sharing SessionStore's SQLite connection.

    Never opens its own `sqlite3.connect()` — the caller (SessionStore)
    passes its own `self._conn` so both tables live in one database file
    and one connection.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    async def initialize(self) -> None:
        """Create the task_registry table + index. Idempotent — safe to re-run."""
        self._conn.row_factory = sqlite3.Row
        await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
        # NOTE: journal_mode persists in the DB file; synchronous does NOT —
        # must be reissued on every new connection (see RESEARCH.md Pitfall #4).
        await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")
        await asyncio.to_thread(
            self._conn.executescript,
            """
            CREATE TABLE IF NOT EXISTS task_registry (
                session_id    TEXT NOT NULL,
                directive_id  TEXT NOT NULL,
                agent_name    TEXT NOT NULL,
                status        TEXT NOT NULL CHECK(status IN ('created','running','completed','failed')),
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                error_detail  TEXT,
                PRIMARY KEY (session_id, directive_id)
            );
            CREATE INDEX IF NOT EXISTS idx_task_registry_session ON task_registry(session_id);
            """,
        )
        await asyncio.to_thread(self._conn.commit)

    async def mark(
        self,
        session_id: str,
        directive_id: str,
        agent_name: str,
        status: str,
        error_detail: Optional[str] = None,
    ) -> None:
        """Upsert directive handoff state.

        Repeated marks for the same (session_id, directive_id) update the
        one row in place (agent_name/status/updated_at/error_detail) rather
        than inserting a duplicate. The table's CHECK constraint rejects any
        `status` outside {created, running, completed, failed} by raising
        `sqlite3.IntegrityError`.
        """
        now = datetime.now(timezone.utc).isoformat()
        await asyncio.to_thread(
            self._conn.execute,
            """
            INSERT INTO task_registry
                (session_id, directive_id, agent_name, status, created_at, updated_at, error_detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, directive_id) DO UPDATE SET
                agent_name   = excluded.agent_name,
                status       = excluded.status,
                updated_at   = excluded.updated_at,
                error_detail = excluded.error_detail
            """,
            (session_id, directive_id, agent_name, status, now, now, error_detail),
        )
        await asyncio.to_thread(self._conn.commit)

    async def detect_stale(self, session_id: str) -> list[sqlite3.Row]:
        """Crash-detection query (03-RESEARCH.md Pattern 2 — verbatim).

        Any row returned means a directive was dispatched but never reported
        completed/failed before the process died. The caller must surface
        this as a resume mismatch (AI-SPEC.md Section 6: "any session-resume
        mismatch -> ERROR, halt further dispatch") — never auto-mark it done.
        """
        rows = await asyncio.to_thread(
            lambda: self._conn.execute(
                "SELECT directive_id, agent_name FROM task_registry "
                "WHERE session_id = ? AND status = 'running'",
                (session_id,),
            ).fetchall()
        )
        return rows
