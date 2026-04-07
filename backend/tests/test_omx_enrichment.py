"""Tests for OmX ResearchKB pre-engagement enrichment."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock


class TestOmXResearchEnrichment:

    @pytest.mark.asyncio
    async def test_plan_includes_research_context_when_kb_has_results(self):
        """When KB returns CVEs for target, plan.metadata includes research_context."""
        from backend.core.omx import OmX
        from backend.intelligence.research_kb import ResearchKBEntry

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(return_value=[
            ResearchKBEntry(
                entry_id="nvd-CVE-2024-1234",
                source="nvd",
                cve_id="CVE-2024-1234",
                description="Apache RCE",
                cvss_score=9.8,
                poc_url="https://github.com/user/poc",
            )
        ])

        from backend.core.models import ScopeConfig
        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert "research_context" in plan.metadata
        assert "CVE-2024-1234" in plan.metadata["research_context"]

    @pytest.mark.asyncio
    async def test_plan_proceeds_when_kb_is_none(self):
        """OmX.plan() works normally when research_kb=None."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        omx = OmX(research_kb=None)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan is not None
        assert plan.metadata.get("research_context") is None

    @pytest.mark.asyncio
    async def test_plan_proceeds_when_kb_query_fails(self):
        """OmX.plan() proceeds gracefully if KB.query() raises."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(side_effect=Exception("DB error"))

        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan is not None  # planning should not crash

    @pytest.mark.asyncio
    async def test_plan_no_context_when_kb_empty(self):
        """No research_context key when KB returns no results."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(return_value=[])

        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan.metadata.get("research_context") is None
