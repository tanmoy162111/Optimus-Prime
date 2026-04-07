"""Tests for BaseAgent run_loop resilience — tool_not_found handling."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.core.base_agent import AgentAction, BaseAgent, ToolResult
from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig


class _SimpleAgent(BaseAgent):
    """Minimal concrete agent for testing."""
    def __init__(self, actions, **kwargs):
        super().__init__(**kwargs)
        self._planned_actions = list(actions)
        self._action_history = []

    async def execute(self, task):
        return await self.run_loop(task)

    async def _plan_next_action(self, task):
        if not self._planned_actions:
            return None
        action = self._planned_actions.pop(0)
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input})
        return action


def _make_task():
    return AgentTask(task_id="t1", agent_class="test", prompt="Execute test against 10.0.0.1")


class TestRunLoopToolNotFound:
    @pytest.mark.asyncio
    async def test_tool_not_found_triggers_alternative(self):
        """When tool_not_found, alternative tool from ToolFallbackResolver is tried."""
        # Primary tool fails with tool_not_found; alternative succeeds
        executor = AsyncMock()
        call_log = []

        async def mock_execute(**kwargs):
            tool = kwargs.get("tool_name")
            call_log.append(tool)
            if tool == "sublist3r":
                return ToolResult(success=True, output={"status": "tool_not_found", "error": "not found"})
            return ToolResult(success=True, output={"stdout": "amass output", "status": "success"})

        executor.execute = mock_execute

        agent = _SimpleAgent(
            actions=[AgentAction("sublist3r", {"target": "example.com"}, "subdomain enum")],
            agent_id="test",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"]),
            tool_executor=executor,
        )

        from backend.core.tool_fallback import ToolFallbackResolver
        agent._tool_fallback_resolver = ToolFallbackResolver()

        result = await agent.execute(_make_task())
        assert "amass" in call_log, f"Alternative tool 'amass' should have been tried. Called: {call_log}"

    @pytest.mark.asyncio
    async def test_tool_not_found_with_no_alternative_skips_gracefully(self):
        """When no alternative exists and install fails, agent skips and continues."""
        executor = AsyncMock()

        action1 = AgentAction("crt_sh", {"target": "example.com"}, "CT logs")
        action2 = AgentAction("whois", {"target": "example.com"}, "whois lookup")
        executor_calls = []

        async def mock_exec(**kwargs):
            executor_calls.append(kwargs.get("tool_name"))
            if kwargs.get("tool_name") == "crt_sh":
                return ToolResult(success=True, output={"status": "tool_not_found"})
            return ToolResult(success=True, output={"stdout": "whois output"})

        executor.execute = mock_exec

        agent = _SimpleAgent(
            actions=[action1, action2],
            agent_id="test",
            agent_type=AgentType.SCOPE_DISCOVERY,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"]),
            tool_executor=executor,
        )
        from backend.core.tool_fallback import ToolFallbackResolver
        agent._tool_fallback_resolver = ToolFallbackResolver()

        result = await agent.execute(_make_task())
        # Agent should continue to whois despite crt_sh failing
        assert "whois" in executor_calls
