"""Tests for ResearchDaemon + ResearchKB + StrategyEvolution (M3).

Validates nightly completion, incremental ingestion, deduplication,
and budget cap enforcement.
"""

from __future__ import annotations

import pytest

from backend.intelligence.research_daemon import (
    ResearchBudgetTracker,
    ResearchDaemon,
)
from backend.intelligence.research_kb import ResearchKB, ResearchKBEntry
from backend.intelligence.strategy_evolution import (
    AttackChain,
    ChainNode,
    StrategyEvolutionEngine,
)
from backend.memory.smart_memory import SmartMemory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def research_kb(tmp_path):
    kb = ResearchKB(db_path=tmp_path / "test_kb.db")
    await kb.initialize()
    yield kb
    await kb.close()


@pytest.fixture
async def smart_memory(tmp_path):
    sm = SmartMemory(
        db_path=tmp_path / "test_memory.db",
        embedding_fn=lambda text: [0.1] * 8,  # Simple mock
    )
    await sm.initialize()
    yield sm
    await sm.close()


def _make_entry(eid: str, source: str, cve_id: str | None = None, **kwargs):
    return ResearchKBEntry(
        entry_id=eid,
        source=source,
        cve_id=cve_id,
        description=kwargs.get("description", f"Test entry {eid}"),
        technique_id=kwargs.get("technique_id"),
        poc_url=kwargs.get("poc_url"),
        affected_products=kwargs.get("affected_products", []),
        cvss_score=kwargs.get("cvss_score"),
    )


# ---------------------------------------------------------------------------
# ResearchKB Tests
# ---------------------------------------------------------------------------

class TestResearchKB:

    @pytest.mark.asyncio
    async def test_ingest_and_query(self, research_kb):
        """Basic ingest and query."""
        entry = _make_entry("e1", "nvd", "CVE-2024-0001")
        await research_kb.ingest(entry)

        results = await research_kb.query(cve_id="CVE-2024-0001")
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    @pytest.mark.asyncio
    async def test_deduplication_by_cve(self, research_kb):
        """Same CVE from two sources merges rather than duplicates."""
        e1 = _make_entry("e1", "nvd", "CVE-2024-0001")
        e2 = _make_entry("e2", "cisa_kev", "CVE-2024-0001")

        await research_kb.ingest(e1)
        await research_kb.ingest(e2)

        count = await research_kb.count()
        assert count == 1  # Only one entry

        results = await research_kb.query(cve_id="CVE-2024-0001")
        assert len(results) == 1
        assert "nvd" in results[0].sources_merged
        assert "cisa_kev" in results[0].sources_merged

    @pytest.mark.asyncio
    async def test_query_by_keyword(self, research_kb):
        await research_kb.ingest(_make_entry("e1", "nvd", "CVE-2024-0001", description="Remote code execution"))
        await research_kb.ingest(_make_entry("e2", "nvd", "CVE-2024-0002", description="SQL injection"))

        results = await research_kb.query(keyword="SQL")
        assert len(results) == 1
        assert "SQL" in results[0].description

    @pytest.mark.asyncio
    async def test_source_state_tracking(self, research_kb):
        """Last run timestamp per source is tracked."""
        await research_kb.set_last_run("nvd", "2024-01-01T00:00:00")
        ts = await research_kb.get_last_run("nvd")
        assert ts == "2024-01-01T00:00:00"

        assert await research_kb.get_last_run("unknown") is None


# ---------------------------------------------------------------------------
# ResearchDaemon Tests
# ---------------------------------------------------------------------------

class TestResearchDaemon:

    @pytest.mark.asyncio
    async def test_nightly_run_completes(self, research_kb):
        """Nightly run with mock sources completes without budget overrun."""
        async def mock_nvd(last_run):
            return [_make_entry("nvd-1", "nvd", "CVE-2024-1001")]

        async def mock_cisa(last_run):
            return [_make_entry("kev-1", "cisa_kev", "CVE-2024-1002")]

        daemon = ResearchDaemon(
            research_kb=research_kb,
            budget=ResearchBudgetTracker(budget=100_000),
            source_adapters={"nvd": mock_nvd, "cisa_kev": mock_cisa},
        )

        result = await daemon.run_nightly()
        assert result["total_ingested"] >= 2
        assert not result["budget_exhausted"]
        assert result["sources"]["nvd"]["status"] == "completed"
        assert result["sources"]["cisa_kev"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_incremental_ingestion(self, research_kb):
        """Second run with same entries deduplicates."""
        call_count = [0]

        async def mock_source(last_run):
            call_count[0] += 1
            return [_make_entry(f"inc-{call_count[0]}", "nvd", "CVE-2024-9999")]

        daemon = ResearchDaemon(
            research_kb=research_kb,
            source_adapters={"nvd": mock_source},
        )

        r1 = await daemon.run_nightly()
        assert r1["total_ingested"] == 1

        r2 = await daemon.run_nightly()
        # Second run: same CVE deduplicates
        assert r2["total_deduplicated"] == 1

        count = await research_kb.count()
        assert count == 1

    @pytest.mark.asyncio
    async def test_budget_cap_enforcement(self, research_kb):
        """Budget exhausted stops further source ingestion."""
        async def mock_source(last_run):
            return [_make_entry(f"budget-test", "nvd", "CVE-2024-8888")]

        daemon = ResearchDaemon(
            research_kb=research_kb,
            budget=ResearchBudgetTracker(budget=100),  # Very low budget
            source_adapters={
                "nvd": mock_source,
                "cisa_kev": mock_source,
                "exploitdb": mock_source,
                "github_poc": mock_source,
                "attack": mock_source,
                "blogs": mock_source,
            },
        )

        result = await daemon.run_nightly()
        assert result["budget_exhausted"] is True

        # Not all sources should complete
        completed = sum(
            1 for s in result["sources"].values()
            if s.get("status") == "completed"
        )
        skipped = sum(
            1 for s in result["sources"].values()
            if s.get("reason") == "budget_exhausted"
        )
        assert completed < 6  # Budget stops before all sources

    @pytest.mark.asyncio
    async def test_missing_adapter_skipped(self, research_kb):
        """Sources without adapters are skipped gracefully."""
        daemon = ResearchDaemon(research_kb=research_kb, source_adapters={})
        result = await daemon.run_nightly()

        for source, status in result["sources"].items():
            assert status["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_cron_registry(self, research_kb):
        """Cron entries are registered and can be triggered."""
        async def mock_source(last_run):
            return []

        daemon = ResearchDaemon(
            research_kb=research_kb,
            source_adapters={"nvd": mock_source},
        )

        entries = daemon.cron.get_entries()
        assert "nightly_research" in entries
        assert "weekly_darkweb" in entries

        result = await daemon.cron.run("nightly_research")
        assert isinstance(result, dict)


class TestResearchBudgetTracker:

    def test_budget_tracking(self):
        tracker = ResearchBudgetTracker(budget=1000)
        assert tracker.remaining == 1000

        assert tracker.record_usage(500)
        assert tracker.remaining == 500

        assert tracker.record_usage(400)
        assert tracker.remaining == 100

        assert not tracker.record_usage(200)  # Would exceed
        assert tracker.remaining == 100

    def test_exhaustion(self):
        tracker = ResearchBudgetTracker(budget=100)
        tracker.record_usage(100)
        assert tracker.is_exhausted

    def test_reset(self):
        tracker = ResearchBudgetTracker(budget=100)
        tracker.record_usage(100)
        assert tracker.is_exhausted
        tracker.reset()
        assert not tracker.is_exhausted
        assert tracker.remaining == 100


# ---------------------------------------------------------------------------
# StrategyEvolutionEngine Tests
# ---------------------------------------------------------------------------

class TestStrategyEvolutionEngine:

    @pytest.mark.asyncio
    async def test_enrich_chain(self, research_kb, smart_memory):
        """Chain enrichment adds PoCs and technique IDs."""
        # Seed ResearchKB
        await research_kb.ingest(ResearchKBEntry(
            entry_id="poc-1", source="exploitdb", cve_id="CVE-2024-5555",
            technique_id="T1190", poc_url="https://exploit-db.com/12345",
            description="RCE via deserialization",
        ))

        # Seed SmartMemory with tool effectiveness
        await smart_memory.store_tool_effectiveness("sqlmap", "sql_injection", 0.92)

        engine = StrategyEvolutionEngine(research_kb, smart_memory)

        chain = AttackChain(
            chain_id="chain-1",
            target="10.0.0.1",
            nodes=[
                ChainNode(
                    step_id="s1", technique="sql_injection",
                    cve_id="CVE-2024-5555", tool="sqlmap",
                ),
                ChainNode(
                    step_id="s2", technique="rce",
                    tool="msfconsole",
                ),
            ],
        )

        enriched = await engine.enrich_chain(chain)
        assert enriched.enrichment_count >= 1

        # First node should have PoC and technique
        n1 = enriched.chain.nodes[0]
        assert n1.attack_technique_id == "T1190"
        assert len(n1.poc_urls) > 0

    @pytest.mark.asyncio
    async def test_enrich_with_empty_kb(self, research_kb, smart_memory):
        """Enrichment with empty KB returns zero enrichments gracefully."""
        engine = StrategyEvolutionEngine(research_kb, smart_memory)
        chain = AttackChain(
            chain_id="chain-empty",
            nodes=[ChainNode(step_id="s1", technique="unknown")],
        )
        enriched = await engine.enrich_chain(chain)
        assert enriched.enrichment_count == 0
