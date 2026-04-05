"""VerificationPolicy — Frozen dataclass enforcing verification limits (N9, Section 7.4).

Hard limits on what the VerificationLoop can do. No agent, hook, or runtime
configuration can mutate it. One operator escape hatch via scope.yaml
verify_tools_extend is XAI-logged.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationPolicy:
    """Immutable policy constraining the VerificationLoop.

    This dataclass is frozen — no agent, hook, or runtime configuration
    can mutate it after creation.

    Attributes:
        allowed_tools: Hardcoded set of tools the VerificationLoop may use.
            - curl: GET only, no auth headers
            - nmap_verify: -sV --open -p {confirmed_port} {confirmed_host} only
            - testssl_readonly: --read-only mode only
            - httpx_probe: -probe flag only
        max_requests_per_finding: Maximum verification attempts per finding.
        allowed_data_extraction: Types of data the VerificationLoop may extract.
        no_auth_injection: When True, CredentialVault.inject() is skipped.
    """

    allowed_tools: frozenset[str] = frozenset({
        "curl",
        "nmap_verify",
        "testssl_readonly",
        "httpx_probe",
    })

    max_requests_per_finding: int = 3

    allowed_data_extraction: frozenset[str] = frozenset({
        "banner_text",
        "http_headers",
        "tls_cert_details",
    })

    no_auth_injection: bool = True

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is in the verification allowlist."""
        return tool_name in self.allowed_tools

    def with_operator_override(self, extra_tool: str) -> VerificationPolicy:
        """Create a new policy with one additional tool (operator escape hatch).

        This is the ONLY way to extend the allowlist, via scope.yaml
        verify_tools_extend (max 1 tool). Must be XAI-logged by the caller.

        Returns:
            New VerificationPolicy with the additional tool.
        """
        return VerificationPolicy(
            allowed_tools=self.allowed_tools | frozenset({extra_tool}),
            max_requests_per_finding=self.max_requests_per_finding,
            allowed_data_extraction=self.allowed_data_extraction,
            no_auth_injection=self.no_auth_injection,
        )


# Singleton default policy — used by VerificationLoop constructor
DEFAULT_VERIFICATION_POLICY = VerificationPolicy()
