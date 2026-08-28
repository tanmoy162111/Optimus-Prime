"""Tests for ResearchKB WAL mode (DATA-01).

Validates that PRAGMA journal_mode=WAL is applied and reads back as
'wal' after initialize(), using a real temp-file sqlite connection
(not mocks).
"""

from __future__ import annotations

import asyncio

import pytest

from backend.intelligence.research_kb import ResearchKB


class TestResearchKBWAL:
    """DATA-01: ResearchKB must apply WAL mode on connect."""

    @pytest.mark.asyncio
    async def test_journal_mode_is_wal(self, tmp_path):
        """After initialize(), journal_mode should read back as 'wal'."""
        kb = ResearchKB(db_path=tmp_path / "kb.db")
        await kb.initialize()
        try:
            row = await asyncio.to_thread(
                kb._conn.execute, "PRAGMA journal_mode"
            )
            result = row.fetchone()
            assert result[0].lower() == "wal"
        finally:
            await kb.close()
