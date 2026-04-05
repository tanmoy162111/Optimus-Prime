"""SmartMemory — Tier 2 semantic memory (Section 9.2).

SQLite + nomic-embed-text vector store for semantic search.
Supports finding embeddings, adaptive learning (tool effectiveness),
and campaign intelligence (cross-engagement pattern detection).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Default embedding dimension for nomic-embed-text
EMBEDDING_DIM = 768


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _serialize_embedding(embedding: list[float]) -> bytes:
    """Serialize a float list to compact binary (little-endian floats)."""
    return struct.pack(f"<{len(embedding)}f", *embedding)


def _deserialize_embedding(data: bytes) -> list[float]:
    """Deserialize binary back to float list."""
    count = len(data) // 4
    return list(struct.unpack(f"<{count}f", data))


class SmartMemory:
    """SQLite + nomic-embed-text vector store for semantic search.

    Provides:
      - Finding storage with embedding-based retrieval
      - Tool effectiveness tracking (AdaptiveLearning)
      - Cross-engagement pattern detection (CampaignIntelligence)
    """

    def __init__(
        self,
        db_path: Path | None = None,
        ollama_url: str = "http://ollama:11434",
        embedding_fn: Any = None,
    ) -> None:
        self._db_path = db_path or Path("data/memory/smart_memory.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ollama_url = ollama_url
        self._embedding_fn = embedding_fn  # Override for testing
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create tables if they don't exist."""
        async with self._lock:
            self._conn = await asyncio.to_thread(
                sqlite3.connect, str(self._db_path), check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            await asyncio.to_thread(
                self._conn.executescript,
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id  TEXT NOT NULL UNIQUE,
                    text        TEXT NOT NULL,
                    embedding   BLOB NOT NULL,
                    metadata    TEXT NOT NULL DEFAULT '{}',
                    client_id   TEXT,
                    engagement_id TEXT,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_client
                    ON findings(client_id);
                CREATE INDEX IF NOT EXISTS idx_findings_engagement
                    ON findings(engagement_id);

                CREATE TABLE IF NOT EXISTS tool_effectiveness (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool        TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    success_rate REAL NOT NULL,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    engagement_id TEXT,
                    client_id   TEXT,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tool_eff_tool
                    ON tool_effectiveness(tool);
                """,
            )
            await asyncio.to_thread(self._conn.commit)

    async def close(self) -> None:
        if self._conn:
            await asyncio.to_thread(self._conn.close)
            self._conn = None

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    async def _embed(self, text: str) -> list[float]:
        """Generate embedding via Ollama nomic-embed-text or override fn."""
        if self._embedding_fn:
            return self._embedding_fn(text)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self._ollama_url}/api/embeddings",
                    json={"model": "nomic-embed-text", "prompt": text},
                )
                resp.raise_for_status()
                return resp.json()["embedding"]
        except Exception as exc:
            logger.warning("SmartMemory: embedding failed, using hash fallback: %s", exc)
            return self._hash_embedding(text)

    @staticmethod
    def _hash_embedding(text: str) -> list[float]:
        """Deterministic fallback embedding based on text hash."""
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        # Expand to EMBEDDING_DIM floats
        result: list[float] = []
        for i in range(EMBEDDING_DIM):
            byte_idx = i % len(h)
            result.append((h[byte_idx] + i) / 255.0 - 0.5)
        norm = math.sqrt(sum(x * x for x in result))
        if norm > 0:
            result = [x / norm for x in result]
        return result

    # ------------------------------------------------------------------
    # Finding Storage & Search
    # ------------------------------------------------------------------

    async def store_finding(
        self,
        finding_id: str,
        embedding_text: str,
        metadata: dict[str, Any] | None = None,
        client_id: str | None = None,
        engagement_id: str | None = None,
    ) -> None:
        """Store a finding with its embedding."""
        if self._conn is None:
            await self.initialize()

        embedding = await self._embed(embedding_text)
        emb_blob = _serialize_embedding(embedding)
        meta_json = json.dumps(metadata or {})
        now = datetime.now(timezone.utc).isoformat()

        async with self._lock:
            await asyncio.to_thread(
                self._conn.execute,
                """
                INSERT OR REPLACE INTO findings
                    (finding_id, text, embedding, metadata, client_id, engagement_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (finding_id, embedding_text, emb_blob, meta_json, client_id, engagement_id, now),
            )
            await asyncio.to_thread(self._conn.commit)

    async def search(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Semantic search — returns top-k findings by cosine similarity."""
        if self._conn is None:
            await self.initialize()

        query_emb = await self._embed(query)

        rows = await asyncio.to_thread(
            lambda: self._conn.execute(
                "SELECT finding_id, text, embedding, metadata, client_id, engagement_id, created_at FROM findings"
            ).fetchall()
        )

        scored: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            stored_emb = _deserialize_embedding(row["embedding"])
            sim = _cosine_similarity(query_emb, stored_emb)
            scored.append((sim, {
                "finding_id": row["finding_id"],
                "text": row["text"],
                "metadata": json.loads(row["metadata"]),
                "client_id": row["client_id"],
                "engagement_id": row["engagement_id"],
                "similarity": round(sim, 4),
            }))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    # ------------------------------------------------------------------
    # AdaptiveLearning — Tool Effectiveness
    # ------------------------------------------------------------------

    async def store_tool_effectiveness(
        self,
        tool: str,
        target_type: str,
        success_rate: float,
        finding_count: int = 0,
        engagement_id: str | None = None,
        client_id: str | None = None,
    ) -> None:
        """Record tool effectiveness for adaptive learning."""
        if self._conn is None:
            await self.initialize()

        now = datetime.now(timezone.utc).isoformat()
        async with self._lock:
            await asyncio.to_thread(
                self._conn.execute,
                """
                INSERT INTO tool_effectiveness
                    (tool, target_type, success_rate, finding_count, engagement_id, client_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tool, target_type, success_rate, finding_count, engagement_id, client_id, now),
            )
            await asyncio.to_thread(self._conn.commit)

    async def get_best_tools(
        self, target_type: str, top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Get most effective tools for a target type (AdaptiveLearning)."""
        if self._conn is None:
            await self.initialize()

        rows = await asyncio.to_thread(
            lambda: self._conn.execute(
                """
                SELECT tool,
                       AVG(success_rate) as avg_rate,
                       SUM(finding_count) as total_findings,
                       COUNT(*) as uses
                FROM tool_effectiveness
                WHERE target_type = ?
                GROUP BY tool
                ORDER BY avg_rate DESC
                LIMIT ?
                """,
                (target_type, top_k),
            ).fetchall()
        )

        return [
            {
                "tool": row["tool"],
                "avg_success_rate": round(row["avg_rate"], 4),
                "total_findings": row["total_findings"],
                "uses": row["uses"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # CampaignIntelligence — Cross-Engagement Patterns
    # ------------------------------------------------------------------

    async def detect_systemic(
        self, client_id: str, min_occurrences: int = 3,
    ) -> list[dict[str, Any]]:
        """Detect systemic weaknesses across engagements for a client.

        Returns findings that appear in >= min_occurrences engagements.
        """
        if self._conn is None:
            await self.initialize()

        rows = await asyncio.to_thread(
            lambda: self._conn.execute(
                """
                SELECT text, metadata,
                       COUNT(DISTINCT engagement_id) as engagement_count,
                       GROUP_CONCAT(DISTINCT engagement_id) as engagements
                FROM findings
                WHERE client_id = ?
                GROUP BY text
                HAVING COUNT(DISTINCT engagement_id) >= ?
                ORDER BY engagement_count DESC
                """,
                (client_id, min_occurrences),
            ).fetchall()
        )

        return [
            {
                "weakness": row["text"],
                "metadata": json.loads(row["metadata"]),
                "engagement_count": row["engagement_count"],
                "engagements": row["engagements"].split(",") if row["engagements"] else [],
            }
            for row in rows
        ]
