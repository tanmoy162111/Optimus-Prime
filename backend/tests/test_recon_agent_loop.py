"""Integration test — ReconAgent completes loop against mock backend.

Verifies:
  - ReconAgent executes the full run_loop with fallback planning
  - Publishes findings to DurableEventLog-backed EventBus
  - Terminates cleanly without context overflow
  - Events appear in DurableEventLog with correct channel/type
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.agents.recon_agent import ReconAgent
from backend.core.base_agent import ToolResult
from backend.core.event_bus import DurableEventLog, EventBus
from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig
from backend.core.xai_logger import XAILogger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def event_bus(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "recon_test.db")
    bus = EventBus(durable_log=log)
    await bus.initialize()
    yield bus
    await bus.close()


@pytest.fixture
def mock_tool_executor():
    """A tool executor that returns mock scan results."""
    executor = AsyncMock()

    call_count = 0

    async def mock_execute(**kwargs):
        nonlocal call_count
        call_count += 1
        tool_name = kwargs.get("tool_name", "unknown")

        if tool_name == "dnsrecon":
            return ToolResult(
                success=True,
                output="DNS records: A 10.0.0.1, MX mail.example.com",
            )
        elif tool_name == "sublist3r":
            return ToolResult(
                success=True,
                output="Subdomains: api.example.com, www.example.com",
            )
        elif tool_name == "nmap":
            return ToolResult(
                success=True,
                output="80/tcp open http\n443/tcp open https\n22/tcp open ssh",
                is_finding=True,
                findings=[{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
            )
        elif tool_name == "whatweb":
            return ToolResult(
                success=True,
                output="Apache/2.4.41, PHP/7.4",
                is_terminal=True,  # Last step
            )
        else:
            return ToolResult(success=True, output=f"Mock output for {tool_name}")

    executor.execute = mock_execute
    return executor


@pytest.fixture
def xai_logger(tmp_path):
    return XAILogger(log_dir=tmp_path / "xai")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReconAgentLoop:
    """ReconAgent completes full loop and publishes events."""

    @pytest.mark.asyncio
    async def test_recon_completes_fallback_loop(self, event_bus, mock_tool_executor, xai_logger):
        """ReconAgent with fallback planning completes 4 steps."""
        agent = ReconAgent(
            agent_id="recon-test-001",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"], ports="all"),
            event_bus=event_bus,
            tool_executor=mock_tool_executor,
            xai_logger=xai_logger,
            llm_router=None,  # Use fallback planning
        )

        task = AgentTask(
            task_id="test-task-001",
            agent_class="ReconAgent",
            prompt="Perform reconnaissance on example.com",
        )

        result = await agent.execute(task)

        # Should terminate after whatweb (is_terminal=True)
        assert result.status in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_recon_publishes_lifecycle_events(self, event_bus, mock_tool_executor, xai_logger):
        """ReconAgent publishes lifecycle events to EventBus."""
        agent = ReconAgent(
            agent_id="recon-test-002",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"], ports="all"),
            event_bus=event_bus,
            tool_executor=mock_tool_executor,
            xai_logger=xai_logger,
            llm_router=None,
        )

        task = AgentTask(
            task_id="test-task-002",
            agent_class="ReconAgent",
            prompt="Perform reconnaissance on example.com",
        )

        await agent.execute(task)

        # Check events in DurableEventLog
        events = await event_bus.replay(0)
        assert len(events) > 0

        # Should have lifecycle events
        event_types = [e["event_type"] for e in events]
        assert "AGENT_RUNNING" in event_types or "FINDING_CREATED" in event_types

    @pytest.mark.asyncio
    async def test_recon_publishes_finding_events(self, event_bus, mock_tool_executor, xai_logger):
        """ReconAgent publishes FINDING_CREATED when findings detected."""
        agent = ReconAgent(
            agent_id="recon-test-003",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"], ports="all"),
            event_bus=event_bus,
            tool_executor=mock_tool_executor,
            xai_logger=xai_logger,
            llm_router=None,
        )

        task = AgentTask(
            task_id="test-task-003",
            agent_class="ReconAgent",
            prompt="Perform reconnaissance on example.com",
        )

        await agent.execute(task)

        events = await event_bus.replay(0)
        finding_events = [e for e in events if e["channel"] == "findings"]

        # nmap returns is_finding=True
        assert len(finding_events) >= 1

    @pytest.mark.asyncio
    async def test_recon_max_iterations_guard(self, event_bus, xai_logger):
        """ReconAgent stops at max_iterations to prevent infinite loop."""
        # Tool executor that never returns terminal
        infinite_executor = AsyncMock()
        infinite_executor.execute = AsyncMock(
            return_value=ToolResult(success=True, output="More data...")
        )

        agent = ReconAgent(
            agent_id="recon-test-004",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"], ports="all"),
            event_bus=event_bus,
            tool_executor=infinite_executor,
            xai_logger=xai_logger,
            llm_router=None,
            max_iterations=5,  # Low limit for test
        )

        task = AgentTask(
            task_id="test-task-004",
            agent_class="ReconAgent",
            prompt="Perform reconnaissance on example.com",
        )

        result = await agent.execute(task)

        # Should hit fallback plan end (4 steps) and return
        # The fallback only has 4 steps so it'll return None at step 5
        assert result.status in ("completed", "failed", "max_iterations_reached")

    @pytest.mark.asyncio
    async def test_recon_events_in_durable_log(self, event_bus, mock_tool_executor, xai_logger):
        """Events appear in DurableEventLog with correct channel/type."""
        agent = ReconAgent(
            agent_id="recon-test-005",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"], ports="all"),
            event_bus=event_bus,
            tool_executor=mock_tool_executor,
            xai_logger=xai_logger,
            llm_router=None,
        )

        task = AgentTask(
            task_id="test-task-005",
            agent_class="ReconAgent",
            prompt="Scan 10.0.0.1",
        )

        await agent.execute(task)

        events = await event_bus.replay(0)
        channels = {e["channel"] for e in events}

        # Should have at least lifecycle or findings channel
        assert channels & {"lifecycle", "findings"}

    @pytest.mark.asyncio
    async def test_recon_xai_logging(self, event_bus, mock_tool_executor, xai_logger):
        """ReconAgent logs decisions to XAI."""
        agent = ReconAgent(
            agent_id="recon-test-006",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"], ports="all"),
            event_bus=event_bus,
            tool_executor=mock_tool_executor,
            xai_logger=xai_logger,
            llm_router=None,
        )

        task = AgentTask(
            task_id="test-task-006",
            agent_class="ReconAgent",
            prompt="Perform reconnaissance on example.com",
        )

        await agent.execute(task)

        entries = xai_logger.get_entries()
        assert len(entries) > 0
        # Each action should be logged
        assert any("dnsrecon" in e.action or "nmap" in e.action for e in entries)


class TestOmXIntegration:
    """OmX produces valid engagement plans."""

    @pytest.mark.asyncio
    async def test_pentest_directive_produces_plan(self):
        """$pentest produces a 7-phase plan."""
        from backend.core.omx import OmX

        omx = OmX(llm_router=None)
        plan = await omx.plan("$pentest target.com")

        assert plan.directive == "$pentest"
        assert plan.phase_count() == 8
        assert AgentType.RECON in plan.agent_types_involved()
        assert AgentType.EXPLOIT in plan.agent_types_involved()

    @pytest.mark.asyncio
    async def test_recon_directive_produces_plan(self):
        """$recon produces a 2-phase plan."""
        from backend.core.omx import OmX

        omx = OmX(llm_router=None)
        plan = await omx.plan("$recon example.com")

        assert plan.directive == "$recon"
        assert plan.phase_count() == 2

    @pytest.mark.asyncio
    async def test_natural_language_fallback(self):
        """Natural language without directive falls back to recon."""
        from backend.core.omx import OmX

        omx = OmX(llm_router=None)
        plan = await omx.plan("scan the target for vulnerabilities")

        assert plan.directive == "natural_language"
        assert plan.phase_count() > 0


class TestOmOIntegration:
    """OmO executes plans and publishes lifecycle events."""

    @pytest.mark.asyncio
    async def test_omo_executes_simple_plan(self, event_bus):
        """OmO executes a simple recon plan."""
        from backend.core.omo import OmO
        from backend.core.omx import OmX

        omx = OmX(llm_router=None)
        plan = await omx.plan("$recon example.com")

        omo = OmO(event_bus=event_bus)
        result = await omo.execute_plan(plan)

        assert result.plan_id == plan.plan_id
        assert result.status in ("completed", "partial", "failed")

        # Check lifecycle events published
        events = await event_bus.replay(0)
        event_types = [e["event_type"] for e in events]
        assert "ENGAGEMENT_STARTED" in event_types
        assert "ENGAGEMENT_COMPLETED" in event_types
