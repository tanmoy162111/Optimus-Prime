"""Tests for IntelAgent StrategyEvolutionEngine enrichment hook."""
from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch


@dataclass
class _FakeAgentResult:
    status: str = "completed"
    findings: list = field(default_factory=list)
    error: str | None = None
    output: str = ""
    tool_calls: list = field(default_factory=list)


class TestIntelAgentEnrichment:

    @pytest.mark.asyncio
    async def test_execute_calls_strategy_engine_when_present(self):
        """IntelAgent.execute() calls strategy_engine.enrich_chain() when provided."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_engine = MagicMock()
        mock_engine.enrich_chain = AsyncMock(return_value=MagicMock(enrichment_count=1, research_sources=["nvd"]))

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(
            status="completed",
            findings=[{
                "cve_id": "CVE-2024-1234",
                "severity": "critical",
                "title": "Apache RCE",
            }],
        ))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=mock_engine,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            await agent.execute(AgentTask(
                task_id="t1",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        mock_engine.enrich_chain.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_works_without_strategy_engine(self):
        """IntelAgent.execute() works normally when strategy_engine=None."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(status="completed"))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=None,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            result = await agent.execute(AgentTask(
                task_id="t2",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        assert result is not None
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_enrich_does_not_crash_on_engine_error(self):
        """Enrichment failure does not crash IntelAgent.execute()."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_engine = MagicMock()
        mock_engine.enrich_chain = AsyncMock(side_effect=Exception("KB down"))

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(
            status="completed",
            findings=[{"cve_id": "CVE-2024-9999", "severity": "high"}],
        ))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=mock_engine,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            result = await agent.execute(AgentTask(
                task_id="t3",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        assert result.status == "completed"  # should not fail
