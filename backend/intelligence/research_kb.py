"""ResearchKB — SQLite knowledge base for research intelligence (Section 15.2).

Stores CVEs, PoCs, ATT&CK techniques, and threat intelligence from
the nightly research daemon with cross-source deduplication.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ResearchKBEntry:
    """Single entry in the research knowledge base (Section 15.2)."""

    entry_id: str
    source: str  # exploitdb, nvd, github_poc, attack, hackerone, blogs, cisa_kev, dark_web
    cve_id: str | None = None
    technique_id: str | None = None  # ATT&CK technique
    poc_url: str | None = None
    affected_products: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    ingested_at: str = ""
    sources_merged: list[str] = field(default_factory=list)


class ResearchKB:
    """SQLite-backed research knowledge base.

    Supports:
      - Ingest with cross-source deduplication by cve_id
      - Flexible querying by cve_id, technique_id, keyword
      - Source tracking for provenance
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("data/research/research_kb.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        async with self._lock:
            self._conn = await asyncio.to_thread(
                sqlite3.connect, str(self._db_path), check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            await asyncio.to_thread(
                self._conn.executescript,
                """
                CREATE TABLE IF NOT EXISTS entries (
                    entry_id          TEXT PRIMARY KEY,
                    source            TEXT NOT NULL,
                    cve_id            TEXT,
                    technique_id      TEXT,
                    poc_url           TEXT,
                    affected_products TEXT NOT NULL DEFAULT '[]',
                    cvss_score        REAL,
                    description       TEXT NOT NULL DEFAULT '',
                    raw_data          TEXT NOT NULL DEFAULT '{}',
                    ingested_at       TEXT NOT NULL,
                    sources_merged    TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_kb_cve ON entries(cve_id);
                CREATE INDEX IF NOT EXISTS idx_kb_technique ON entries(technique_id);
                CREATE INDEX IF NOT EXISTS idx_kb_source ON entries(source);

                CREATE TABLE IF NOT EXISTS source_state (
                    source      TEXT PRIMARY KEY,
                    last_run_at TEXT NOT NULL
                );
                """,
            )
            await asyncio.to_thread(self._conn.commit)

    async def close(self) -> None:
        if self._conn:
            await asyncio.to_thread(self._conn.close)
            self._conn = None

    async def ingest(self, entry: ResearchKBEntry) -> str:
        """Ingest a research entry with deduplication by cve_id.

        If the same cve_id already exists from a different source,
        merges the sources list rather than creating a duplicate.

        Returns the entry_id (existing or new).
        """
        if self._conn is None:
            await self.initialize()

        now = datetime.now(timezone.utc).isoformat()
        entry.ingested_at = entry.ingested_at or now

        async with self._lock:
            # Check for existing entry with same cve_id
            if entry.cve_id:
                existing = await asyncio.to_thread(
                    lambda: self._conn.execute(
                        "SELECT entry_id, sources_merged FROM entries WHERE cve_id = ?",
                        (entry.cve_id,),
                    ).fetchone()
                )
                if existing:
                    # Merge sources
                    merged = json.loads(existing["sources_merged"])
                    if entry.source not in merged:
                        merged.append(entry.source)
                        await asyncio.to_thread(
                            self._conn.execute,
                            "UPDATE entries SET sources_merged = ? WHERE entry_id = ?",
                            (json.dumps(merged), existing["entry_id"]),
                        )
                        await asyncio.to_thread(self._conn.commit)
                    return existing["entry_id"]

            # New entry
            if not entry.sources_merged:
                entry.sources_merged = [entry.source]

            await asyncio.to_thread(
                self._conn.execute,
                """
                INSERT OR REPLACE INTO entries
                    (entry_id, source, cve_id, technique_id, poc_url,
                     affected_products, cvss_score, description, raw_data,
                     ingested_at, sources_merged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.entry_id,
                    entry.source,
                    entry.cve_id,
                    entry.technique_id,
                    entry.poc_url,
                    json.dumps(entry.affected_products),
                    entry.cvss_score,
                    entry.description,
                    json.dumps(entry.raw_data),
                    entry.ingested_at,
                    json.dumps(entry.sources_merged),
                ),
            )
            await asyncio.to_thread(self._conn.commit)
            return entry.entry_id

    async def query(
        self,
        cve_id: str | None = None,
        technique_id: str | None = None,
        keyword: str | None = None,
        source: str | None = None,
        limit: int = 50,
    ) -> list[ResearchKBEntry]:
        """Query the knowledge base with flexible filters."""
        if self._conn is None:
            await self.initialize()

        conditions: list[str] = []
        params: list[Any] = []

        if cve_id:
            conditions.append("cve_id = ?")
            params.append(cve_id)
        if technique_id:
            conditions.append("technique_id = ?")
            params.append(technique_id)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if keyword:
            conditions.append("(description LIKE ? OR cve_id LIKE ?)")
            params.extend([f"%{keyword}%", f"%{keyword}%"])

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM entries {where} ORDER BY ingested_at DESC LIMIT ?"
        params.append(limit)

        rows = await asyncio.to_thread(
            lambda: self._conn.execute(sql, params).fetchall()
        )

        return [self._row_to_entry(row) for row in rows]

    async def count(self) -> int:
        if self._conn is None:
            await self.initialize()
        row = await asyncio.to_thread(
            lambda: self._conn.execute("SELECT COUNT(*) as cnt FROM entries").fetchone()
        )
        return row["cnt"]

    async def get_last_run(self, source: str) -> str | None:
        """Get the last run timestamp for a source."""
        if self._conn is None:
            await self.initialize()
        row = await asyncio.to_thread(
            lambda: self._conn.execute(
                "SELECT last_run_at FROM source_state WHERE source = ?", (source,),
            ).fetchone()
        )
        return row["last_run_at"] if row else None

    async def set_last_run(self, source: str, timestamp: str) -> None:
        """Update the last run timestamp for a source."""
        if self._conn is None:
            await self.initialize()
        async with self._lock:
            await asyncio.to_thread(
                self._conn.execute,
                "INSERT OR REPLACE INTO source_state (source, last_run_at) VALUES (?, ?)",
                (source, timestamp),
            )
            await asyncio.to_thread(self._conn.commit)

    def _row_to_entry(self, row: sqlite3.Row) -> ResearchKBEntry:
        return ResearchKBEntry(
            entry_id=row["entry_id"],
            source=row["source"],
            cve_id=row["cve_id"],
            technique_id=row["technique_id"],
            poc_url=row["poc_url"],
            affected_products=json.loads(row["affected_products"]),
            cvss_score=row["cvss_score"],
            description=row["description"],
            raw_data=json.loads(row["raw_data"]),
            ingested_at=row["ingested_at"],
            sources_merged=json.loads(row["sources_merged"]),
        )
