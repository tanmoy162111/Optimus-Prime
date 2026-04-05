"""EventBus with DurableEventLog — SQLite-backed event system (Section 10, N6).

Every event is written to a SQLite append-log before delivery. No finding
is lost to a backend restart. The frontend reconnects by sending its last
acknowledged sequence number; the EventBus replays all events since.

Cloud swap: DurableEventLog uses an abstract backing interface. The SQLite
implementation is the local deployment backend. Redis Streams is the cloud
migration swap. Tagged with TODO:CLOUD-SWAP.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

# Prune events older than this (Section 10.3)
PRUNE_AGE_HOURS = 24


class DurableEventLog:
    """SQLite append-log for event persistence (Section 10.1).

    Schema:
      seq          INTEGER PRIMARY KEY AUTOINCREMENT
      channel      TEXT
      event_type   TEXT
      payload      JSON (never contains credentials)
      published_at DATETIME
      acked_by     JSON (set of subscriber IDs)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("data/events/event_log.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create the events table if it doesn't exist."""
        async with self._lock:
            self._conn = await asyncio.to_thread(
                sqlite3.connect, str(self._db_path), check_same_thread=False
            )
            await asyncio.to_thread(
                self._conn.execute,
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel      TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    payload      TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    acked_by     TEXT NOT NULL DEFAULT '[]'
                )
                """,
            )
            await asyncio.to_thread(
                self._conn.execute,
                "CREATE INDEX IF NOT EXISTS idx_events_channel ON events(channel)",
            )
            await asyncio.to_thread(
                self._conn.execute,
                "CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq)",
            )
            await asyncio.to_thread(self._conn.commit)

    async def append(
        self,
        channel: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> int:
        """Append an event to the log. Returns the sequence number."""
        async with self._lock:
            if self._conn is None:
                await self.initialize()

            now = datetime.now(timezone.utc).isoformat()
            payload_json = json.dumps(payload)

            cursor = await asyncio.to_thread(
                self._conn.execute,
                """
                INSERT INTO events (channel, event_type, payload, published_at)
                VALUES (?, ?, ?, ?)
                """,
                (channel, event_type, payload_json, now),
            )
            await asyncio.to_thread(self._conn.commit)
            return cursor.lastrowid

    async def replay(self, last_seq: int = 0) -> list[dict[str, Any]]:
        """Replay all events with seq > last_seq (Section 10.3)."""
        async with self._lock:
            if self._conn is None:
                await self.initialize()

            cursor = await asyncio.to_thread(
                self._conn.execute,
                "SELECT seq, channel, event_type, payload, published_at FROM events WHERE seq > ? ORDER BY seq",
                (last_seq,),
            )
            rows = await asyncio.to_thread(cursor.fetchall)

        return [
            {
                "seq": row[0],
                "channel": row[1],
                "event_type": row[2],
                "payload": json.loads(row[3]),
                "published_at": row[4],
            }
            for row in rows
        ]

    async def prune(self, max_age_hours: int = PRUNE_AGE_HOURS) -> int:
        """Remove events older than max_age_hours. Returns count removed."""
        async with self._lock:
            if self._conn is None:
                return 0

            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
            ).isoformat()

            cursor = await asyncio.to_thread(
                self._conn.execute,
                "DELETE FROM events WHERE published_at < ?",
                (cutoff,),
            )
            await asyncio.to_thread(self._conn.commit)
            removed = cursor.rowcount
            if removed:
                logger.info("DurableEventLog: pruned %d events older than %dh", removed, max_age_hours)
            return removed

    async def acknowledge(self, seq: int, subscriber_id: str) -> None:
        """Mark an event as acknowledged by a subscriber."""
        async with self._lock:
            if self._conn is None:
                return

            cursor = await asyncio.to_thread(
                self._conn.execute,
                "SELECT acked_by FROM events WHERE seq = ?",
                (seq,),
            )
            row = await asyncio.to_thread(cursor.fetchone)
            if row:
                acked = json.loads(row[0])
                if subscriber_id not in acked:
                    acked.append(subscriber_id)
                    await asyncio.to_thread(
                        self._conn.execute,
                        "UPDATE events SET acked_by = ? WHERE seq = ?",
                        (json.dumps(acked), seq),
                    )
                    await asyncio.to_thread(self._conn.commit)

    async def close(self) -> None:
        """Close the database connection."""
        async with self._lock:
            if self._conn:
                await asyncio.to_thread(self._conn.close)
                self._conn = None


class EventBus:
    """Event publish/subscribe system backed by DurableEventLog.

    Channels (Section 10.2):
      - findings:  FINDING_CREATED, FINDING_VERIFIED, FINDING_CLASSIFIED
      - lifecycle: AGENT_SPAWNED, AGENT_RUNNING, AGENT_FINISHED, AGENT_FAILED
      - intel:     CVE_CORRELATED, ATTACK_MAPPED, DARK_WEB_HIT
      - collab:    USER_JOINED, ROLE_ELEVATED, COMMAND_BROADCAST
      - research:  NEW_CVE_ALERT, POC_DETECTED, TECHNIQUE_DELTA
      - system:    KALI_UNREACHABLE, TOOL_TIMEOUT, TOKEN_BUDGET_WARNING, MERGE_COMPLETE
    """

    def __init__(self, durable_log: DurableEventLog | None = None) -> None:
        self._log = durable_log or DurableEventLog()
        self._subscribers: dict[str, list[Callable[..., Awaitable[None]]]] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the backing store."""
        await self._log.initialize()
        self._initialized = True

    def subscribe(
        self,
        channel: str,
        callback: Callable[..., Awaitable[None]],
    ) -> None:
        """Subscribe to events on a channel."""
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        self._subscribers[channel].append(callback)

    async def publish(
        self,
        channel: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> int:
        """Publish an event — writes to SQLite BEFORE delivery.

        Returns:
            Sequence number of the persisted event.
        """
        if not self._initialized:
            await self.initialize()

        # Write to durable log FIRST (Section 10.1 guarantee)
        seq = await self._log.append(channel, event_type, payload)

        # Then deliver to subscribers
        event = {
            "seq": seq,
            "channel": channel,
            "event_type": event_type,
            "payload": payload,
        }

        for callback in self._subscribers.get(channel, []):
            try:
                await callback(event)
            except Exception as exc:
                logger.error(
                    "EventBus: subscriber failed on %s/%s: %s",
                    channel, event_type, exc,
                )

        return seq

    async def replay(self, last_seq: int = 0) -> list[dict[str, Any]]:
        """Replay all events since last_seq for reconnection."""
        return await self._log.replay(last_seq)

    async def prune(self) -> int:
        """Prune old events (24h default)."""
        return await self._log.prune()

    async def close(self) -> None:
        """Close the event bus and backing store."""
        await self._log.close()
