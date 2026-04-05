"""Suite 1 — VerificationPolicy unit tests (T1).

Section 18.1: test_verification_policy.py.
"""

from __future__ import annotations

import pytest

from backend.core.credential_vault import CredentialVault
from backend.core.exceptions import ToolPermissionError
from backend.core.models import AgentType
from backend.core.namespace_enforcer import NamespaceEnforcer
from backend.verification.verification_policy import (
    DEFAULT_VERIFICATION_POLICY,
    VerificationPolicy,
)


class TestVerificationPolicy:
    """VerificationLoop constraints are enforced."""

    def test_policy_is_frozen(self):
        """VerificationPolicy cannot be mutated."""
        policy = DEFAULT_VERIFICATION_POLICY
        with pytest.raises(AttributeError):
            policy.allowed_tools = frozenset({"sqlmap"})

    def test_allowed_tools_are_correct(self):
        policy = DEFAULT_VERIFICATION_POLICY
        assert policy.allowed_tools == frozenset({
            "curl", "nmap_verify", "testssl_readonly", "httpx_probe",
        })

    def test_max_requests_per_finding(self):
        policy = DEFAULT_VERIFICATION_POLICY
        assert policy.max_requests_per_finding == 3

    def test_no_auth_injection(self):
        policy = DEFAULT_VERIFICATION_POLICY
        assert policy.no_auth_injection is True

    def test_sqlmap_not_allowed(self):
        """VerificationLoop cannot call sqlmap."""
        policy = DEFAULT_VERIFICATION_POLICY
        assert not policy.is_tool_allowed("sqlmap")

    def test_msfconsole_not_allowed(self):
        """VerificationLoop cannot call msfconsole."""
        policy = DEFAULT_VERIFICATION_POLICY
        assert not policy.is_tool_allowed("msfconsole")

    def test_dalfox_not_allowed(self):
        """VerificationLoop cannot call dalfox."""
        policy = DEFAULT_VERIFICATION_POLICY
        assert not policy.is_tool_allowed("dalfox")

    def test_curl_is_allowed(self):
        policy = DEFAULT_VERIFICATION_POLICY
        assert policy.is_tool_allowed("curl")

    def test_nmap_verify_is_allowed(self):
        policy = DEFAULT_VERIFICATION_POLICY
        assert policy.is_tool_allowed("nmap_verify")

    def test_operator_override_adds_one_tool(self):
        """Operator escape hatch adds exactly one tool."""
        policy = DEFAULT_VERIFICATION_POLICY
        extended = policy.with_operator_override("nikto")
        assert extended.is_tool_allowed("nikto")
        assert extended.is_tool_allowed("curl")  # Original still there
        assert not extended.is_tool_allowed("sqlmap")  # Still blocked

    def test_operator_override_preserves_immutability(self):
        """Original policy unchanged after override."""
        policy = DEFAULT_VERIFICATION_POLICY
        _ = policy.with_operator_override("nikto")
        assert not policy.is_tool_allowed("nikto")

    @pytest.mark.asyncio
    async def test_credential_vault_skips_verification_loop(self):
        """CredentialVault.inject() returns unmodified input for VERIFICATION_LOOP."""
        vault = CredentialVault()
        vault.load_credentials({"aws": {"access_key": "AKIATEST"}})

        result = await vault.inject(
            {"target": "10.0.0.1", "port": 80},
            caller=AgentType.VERIFICATION_LOOP,
            provider="aws",
        )
        assert "_credentials" not in result
        assert result == {"target": "10.0.0.1", "port": 80}


class TestVerificationNamespaceEnforcement:
    """VerificationLoop can only use its allowed tools via NamespaceEnforcer."""

    def test_verification_tools_pass_namespace(self):
        allowed = DEFAULT_VERIFICATION_POLICY.allowed_tools
        for tool in ["curl", "nmap_verify", "testssl_readonly", "httpx_probe"]:
            NamespaceEnforcer.check(tool, allowed, "verification-loop")

    def test_exploit_tools_blocked_for_verification(self):
        allowed = DEFAULT_VERIFICATION_POLICY.allowed_tools
        for tool in ["sqlmap", "msfconsole", "dalfox", "masscan", "nuclei", "nmap"]:
            with pytest.raises(ToolPermissionError):
                NamespaceEnforcer.check(tool, allowed, "verification-loop")
