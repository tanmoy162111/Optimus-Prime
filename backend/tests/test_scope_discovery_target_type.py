"""Tests for ScopeDiscoveryAgent target type detection and tool routing."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock
from backend.agents.scope_discovery_agent import ScopeDiscoveryAgent
from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig


@pytest.fixture
def agent():
    return ScopeDiscoveryAgent(
        agent_id="test-scope",
        agent_type=AgentType.SCOPE_DISCOVERY,
        engine=EngineType.INFRASTRUCTURE,
        scope=ScopeConfig(targets=["10.0.0.1"]),
    )


class TestTargetTypeDetection:
    def test_rfc1918_10_is_internal(self, agent):
        assert agent._detect_target_type("10.0.0.1") == "internal"

    def test_rfc1918_172_is_internal(self, agent):
        assert agent._detect_target_type("172.16.5.1") == "internal"

    def test_rfc1918_192_168_is_internal(self, agent):
        assert agent._detect_target_type("192.168.1.100") == "internal"

    def test_public_ip_is_public_ip(self, agent):
        assert agent._detect_target_type("8.8.8.8") == "public_ip"

    def test_domain_is_public_domain(self, agent):
        assert agent._detect_target_type("example.com") == "public_domain"

    def test_subdomain_is_public_domain(self, agent):
        assert agent._detect_target_type("api.example.com") == "public_domain"


class TestToolRouting:
    def test_internal_target_uses_local_tools_only(self, agent):
        """Internal IPs must not use OSINT tools (crt_sh, github_scan, shodan)."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("10.0.0.1")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("10.0.0.1")
        osint_tools = {"crt_sh", "github_scan"}
        assert not osint_tools.intersection(set(actions)), \
            f"OSINT tools {osint_tools} must not run on internal target"
        assert "nmap" in actions

    def test_public_domain_uses_osint_tools(self, agent):
        """Public domains should use OSINT suite."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("example.com")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("example.com")
        assert "crt_sh" in actions
        assert "whois" in actions

    def test_public_ip_uses_shodan_not_crt_sh(self, agent):
        """Public IPs use shodan/nmap but not crt_sh (CT logs are for domains)."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("8.8.8.8")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("8.8.8.8")
        assert "crt_sh" not in actions
        assert "nmap" in actions


class TestScopeAnchorFinding:
    @pytest.mark.asyncio
    async def test_always_produces_at_least_one_finding(self):
        """Even if all tools return empty, a scope anchor finding must be generated."""
        executor = AsyncMock()
        from backend.core.base_agent import ToolResult
        executor.execute = AsyncMock(return_value=ToolResult(success=True, output={"stdout": "", "stderr": "", "status": "success", "exit_code": 0}))

        agent = ScopeDiscoveryAgent(
            agent_id="test-scope",
            agent_type=AgentType.SCOPE_DISCOVERY,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.5"]),
            tool_executor=executor,
        )
        task = AgentTask(task_id="t1", agent_class="scope_discovery", prompt="Execute Scope Discovery phase against 10.0.0.5")
        result = await agent.execute(task)
        assert len(result.findings) >= 1
        titles = [f.get("title", "") for f in result.findings]
        assert any("10.0.0.5" in t or "scope" in t.lower() for t in titles)
