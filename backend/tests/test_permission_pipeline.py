"""Suite 1 — Permission pipeline unit tests (T1).

Tests the full 7-layer permission pipeline end-to-end.
Section 18.1: test_permission_pipeline.py.
"""

from __future__ import annotations

import pytest

from backend.core.credential_vault import CredentialVault
from backend.core.exceptions import (
    ScopeViolationError,
    StealthViolationError,
    ToolPermissionError,
)
from backend.core.hook_runner import HookRunner
from backend.core.models import (
    AgentType,
    EngineType,
    PermissionMode,
    ScopeConfig,
    StealthLevel,
    StealthProfile,
    ToolBackendType,
)
from backend.core.namespace_enforcer import NamespaceEnforcer
from backend.core.permission import PermissionEnforcer, PermissionPipeline
from backend.core.scope_enforcer import ScopeEnforcer
from backend.core.stealth_enforcer import StealthEnforcer
from backend.core.xai_logger import XAILogger
from backend.tools.tool_spec import ToolSpec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scope():
    return ScopeConfig(
        targets=["192.168.1.0/24", "example.com", "*.example.com"],
        excluded_targets=["192.168.1.1"],
        ports=[80, 443, 8080],
        protocols=["tcp", "udp"],
        stealth_level=StealthLevel.MEDIUM,
    )


@pytest.fixture
def high_stealth_scope():
    return ScopeConfig(
        targets=["10.0.0.0/8"],
        stealth_level=StealthLevel.HIGH,
    )


@pytest.fixture
def recon_allowed_tools():
    return frozenset({"nmap", "whatweb", "dnsrecon", "sublist3r", "amass"})


@pytest.fixture
def nmap_spec():
    return ToolSpec(
        name="nmap",
        description="Network mapper",
        input_schema={},
        required_permission=PermissionMode.EXECUTE,
        backend=ToolBackendType.KALI_SSH,
        stealth_profile=StealthProfile(min_stealth_level=StealthLevel.LOW),
        engine_scope=(EngineType.INFRASTRUCTURE,),
        timeout_seconds=300,
    )


@pytest.fixture
def masscan_spec():
    return ToolSpec(
        name="masscan",
        description="High-speed port scanner",
        input_schema={},
        required_permission=PermissionMode.EXECUTE,
        backend=ToolBackendType.KALI_SSH,
        stealth_profile=StealthProfile(min_stealth_level=StealthLevel.LOW),
        engine_scope=(EngineType.INFRASTRUCTURE,),
        timeout_seconds=120,
    )


@pytest.fixture
def pipeline(tmp_path):
    vault = CredentialVault()
    vault.load_credentials({"aws": {"access_key": "AKIAEXAMPLE", "secret_key": "wJalrXUtnFEMI"}})
    return PermissionPipeline(
        permission_enforcer=PermissionEnforcer(),
        credential_vault=vault,
        hook_runner=HookRunner(),
    )


@pytest.fixture
def xai_logger(tmp_path):
    return XAILogger(log_dir=tmp_path / "xai")


# ---------------------------------------------------------------------------
# Layer 2: ScopeEnforcer tests
# ---------------------------------------------------------------------------

class TestScopeEnforcer:
    """Out-of-scope target rejected at ScopeEnforcer."""

    def test_in_scope_ip(self, scope):
        # Should not raise
        ScopeEnforcer.check(scope, {"target": "192.168.1.100", "port": 80})

    def test_out_of_scope_ip_rejected(self, scope):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            ScopeEnforcer.check(scope, {"target": "10.0.0.1"})

    def test_excluded_target_rejected(self, scope):
        with pytest.raises(ScopeViolationError, match="exclusion list"):
            ScopeEnforcer.check(scope, {"target": "192.168.1.1"})

    def test_in_scope_domain(self, scope):
        ScopeEnforcer.check(scope, {"target": "example.com"})

    def test_in_scope_subdomain(self, scope):
        ScopeEnforcer.check(scope, {"target": "sub.example.com"})

    def test_out_of_scope_domain_rejected(self, scope):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            ScopeEnforcer.check(scope, {"target": "evil.com"})

    def test_out_of_scope_port_rejected(self, scope):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            ScopeEnforcer.check(scope, {"target": "192.168.1.100", "port": 22})

    def test_out_of_scope_protocol_rejected(self, scope):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            ScopeEnforcer.check(scope, {"target": "192.168.1.100", "protocol": "icmp"})

    def test_url_target_extraction(self, scope):
        ScopeEnforcer.check(scope, {"target": "http://example.com/path"})

    def test_cidr_match(self, scope):
        ScopeEnforcer.check(scope, {"target": "192.168.1.254"})

    def test_all_ports_allowed(self):
        scope = ScopeConfig(targets=["10.0.0.1"], ports="all")
        ScopeEnforcer.check(scope, {"target": "10.0.0.1", "port": 65535})


# ---------------------------------------------------------------------------
# Layer 4: StealthEnforcer tests
# ---------------------------------------------------------------------------

class TestStealthEnforcer:
    """High-stealth blocks masscan and aggressive nmap."""

    def test_high_stealth_blocks_masscan(self):
        with pytest.raises(StealthViolationError, match="blocked at stealth level HIGH"):
            StealthEnforcer.check(
                "masscan",
                StealthLevel.HIGH,
                StealthProfile(min_stealth_level=StealthLevel.LOW),
            )

    def test_high_stealth_blocks_shodan(self):
        with pytest.raises(StealthViolationError, match="blocked at stealth level HIGH"):
            StealthEnforcer.check(
                "shodan",
                StealthLevel.HIGH,
                StealthProfile(min_stealth_level=StealthLevel.LOW),
            )

    def test_high_stealth_blocks_dark_web(self):
        with pytest.raises(StealthViolationError, match="blocked at stealth level HIGH"):
            StealthEnforcer.check(
                "dark_web_query",
                StealthLevel.HIGH,
                StealthProfile(min_stealth_level=StealthLevel.LOW),
            )

    def test_medium_stealth_allows_nmap_rate_limited(self):
        result = StealthEnforcer.check(
            "nmap",
            StealthLevel.MEDIUM,
            StealthProfile(min_stealth_level=StealthLevel.LOW),
        )
        assert result["rate_limited"] is True

    def test_low_stealth_allows_all(self):
        result = StealthEnforcer.check(
            "masscan",
            StealthLevel.LOW,
            StealthProfile(min_stealth_level=StealthLevel.LOW),
        )
        assert result["rate_limited"] is False


# ---------------------------------------------------------------------------
# Layer 5: NamespaceEnforcer tests
# ---------------------------------------------------------------------------

class TestNamespaceEnforcer:
    """Agent calling out-of-namespace tool raises ToolPermissionError."""

    def test_allowed_tool_passes(self, recon_allowed_tools):
        # Should not raise
        NamespaceEnforcer.check("nmap", recon_allowed_tools, "recon-001")

    def test_out_of_namespace_raises(self, recon_allowed_tools):
        with pytest.raises(ToolPermissionError, match="not in its allowed namespace"):
            NamespaceEnforcer.check("sqlmap", recon_allowed_tools, "recon-001")

    def test_exploit_tool_blocked_for_recon(self, recon_allowed_tools):
        with pytest.raises(ToolPermissionError):
            NamespaceEnforcer.check("msfconsole", recon_allowed_tools, "recon-001")


# ---------------------------------------------------------------------------
# Layer 3: CredentialVault tests
# ---------------------------------------------------------------------------

class TestCredentialVault:
    """Credential never appears in any XAI log entry."""

    @pytest.mark.asyncio
    async def test_verification_loop_gets_no_credentials(self):
        vault = CredentialVault()
        vault.load_credentials({"aws": {"access_key": "AKIAEXAMPLE"}})

        result = await vault.inject(
            {"target": "10.0.0.1"},
            caller=AgentType.VERIFICATION_LOOP,
            provider="aws",
        )
        assert "_credentials" not in result

    @pytest.mark.asyncio
    async def test_normal_agent_gets_credentials(self):
        vault = CredentialVault()
        vault.load_credentials({"aws": {"access_key": "AKIAEXAMPLE"}})

        result = await vault.inject(
            {"target": "10.0.0.1"},
            caller=AgentType.CLOUD,
            provider="aws",
        )
        assert "_credentials" in result

    @pytest.mark.asyncio
    async def test_credentials_never_in_xai(self, xai_logger):
        """Verify credentials are stripped from XAI log entries."""
        entry = await xai_logger.log_decision(
            agent="TestAgent",
            action="scoutsuite password=SuperSecret123 target=10.0.0.1",
            result_summary="Scan found api_key=sk-hidden-key",
            reasoning="Testing credential redaction",
            metadata={"_credentials": {"key": "value"}, "normal_field": "ok"},
        )
        assert entry.credential_present is False
        assert "SuperSecret123" not in entry.action
        assert "sk-hidden-key" not in entry.result_summary

        # Check persisted entries
        entries = xai_logger.get_entries()
        for e in entries:
            assert e.credential_present is False


# ---------------------------------------------------------------------------
# Full pipeline integration test
# ---------------------------------------------------------------------------

class TestPermissionPipelineLayers:
    """All 7 pipeline layers execute in correct order."""

    @pytest.mark.asyncio
    async def test_full_pipeline_allows_valid_call(self, pipeline, scope, nmap_spec):
        result = await pipeline.enforce_pre_execution(
            tool_spec=nmap_spec,
            tool_input={"target": "192.168.1.100", "port": 80},
            scope=scope,
            stealth_level=StealthLevel.MEDIUM,
            allowed_tools=frozenset({"nmap", "whatweb"}),
            agent_id="recon-001",
            agent_type=AgentType.RECON,
        )
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_pipeline_rejects_out_of_scope(self, pipeline, scope, nmap_spec):
        with pytest.raises(ScopeViolationError):
            await pipeline.enforce_pre_execution(
                tool_spec=nmap_spec,
                tool_input={"target": "10.0.0.1"},
                scope=scope,
                stealth_level=StealthLevel.MEDIUM,
                allowed_tools=frozenset({"nmap"}),
                agent_id="recon-001",
                agent_type=AgentType.RECON,
            )

    @pytest.mark.asyncio
    async def test_pipeline_rejects_out_of_namespace(self, pipeline, scope, nmap_spec):
        with pytest.raises(ToolPermissionError):
            await pipeline.enforce_pre_execution(
                tool_spec=nmap_spec,
                tool_input={"target": "192.168.1.100"},
                scope=scope,
                stealth_level=StealthLevel.MEDIUM,
                allowed_tools=frozenset({"sqlmap"}),  # nmap not in allowed
                agent_id="exploit-001",
                agent_type=AgentType.EXPLOIT,
            )

    @pytest.mark.asyncio
    async def test_pipeline_rejects_stealth_violation(self, pipeline, high_stealth_scope, masscan_spec):
        with pytest.raises(StealthViolationError):
            await pipeline.enforce_pre_execution(
                tool_spec=masscan_spec,
                tool_input={"target": "10.0.0.1"},
                scope=high_stealth_scope,
                stealth_level=StealthLevel.HIGH,
                allowed_tools=frozenset({"masscan"}),
                agent_id="scan-001",
                agent_type=AgentType.SCAN,
            )
