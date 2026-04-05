"""ToolSpec — frozen dataclass defining tool metadata, permissions, and timeouts.

Per Section 6.1 of the v2.0 architecture. Each tool declares its own
timeout_seconds based on expected execution time (N3).
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.core.models import (
    EngineType,
    PermissionMode,
    StealthLevel,
    StealthProfile,
    ToolBackendType,
    ToolPromotion,
)

# ---------------------------------------------------------------------------
# Per-tool timeout lookup table (Section 6.4)
# ---------------------------------------------------------------------------

TOOL_TIMEOUT_TABLE: dict[str, int] = {
    # ML Runtime tools
    "promptfoo": 120,
    "art_fgsm": 600,
    "art_pgd": 600,
    "art_cw": 900,
    "model_extract": 1800,
    "membership_infer": 300,
    "model_audit": 240,
    "canary_inject": 120,
    "rag_poison": 120,
    "agent_hijack": 120,
    # ICS tools
    "plcscan": 120,
    "modbus_read": 60,
    "dnp3_probe": 60,
    "ics_fingerprint": 60,
    # Infrastructure tools (generally fast)
    "nmap": 300,
    "nmap_verify": 30,
    "whatweb": 60,
    "dnsrecon": 120,
    "sublist3r": 120,
    "amass": 300,
    "nikto": 300,
    "nuclei": 300,
    "masscan": 120,
    "wpscan": 180,
    "sqlmap": 600,
    "dalfox": 300,
    "commix": 300,
    "ffuf": 300,
    "msfconsole": 600,
    "payload_crafter": 120,
    "scoutsuite": 600,
    "prowler": 600,
    "pacu": 300,
    "jwt_tool": 60,
    "oauthscan": 120,
    "saml_raider": 120,
    "modlishka": 120,
    "o365spray": 120,
    "trufflehog": 180,
    "gitleaks": 180,
    "testssl": 120,
    "testssl_readonly": 60,
    "pii_parser": 60,
    "exfil_sim": 120,
    "sharp_edr_checker": 60,
    "lotl_crafter": 120,
    # Intel tools
    "shodan": 60,
    "cve_search": 30,
    "exploit_db": 30,
    "dark_web_query": 120,
    # Scope discovery tools
    "crt_sh": 30,
    "whois": 30,
    "dns_enum": 60,
    "github_scan": 120,
    # Verification tools
    "curl": 15,
    "httpx_probe": 30,
}

DEFAULT_TOOL_TIMEOUT: int = 60


def get_tool_timeout(tool_name: str) -> int:
    """Return the configured timeout for a tool, or the default."""
    return TOOL_TIMEOUT_TABLE.get(tool_name, DEFAULT_TOOL_TIMEOUT)


# ---------------------------------------------------------------------------
# ToolSpec frozen dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    """Immutable specification for a security tool (Section 6.1).

    Attributes:
        name: Canonical tool identifier.
        description: Human-readable description of the tool's purpose.
        input_schema: JSON Schema dict for input validation.
        required_permission: Minimum permission tier to execute.
        backend: Which backend executes this tool.
        stealth_profile: Stealth constraints for this tool.
        engine_scope: Which engines may use this tool.
        timeout_seconds: Per-tool timeout — replaces the universal 60s cap (v2.0 N3).
        promotion_state: Custom tool lifecycle state.
    """
    name: str
    description: str
    input_schema: dict
    required_permission: PermissionMode
    backend: ToolBackendType
    stealth_profile: StealthProfile
    engine_scope: tuple[EngineType, ...]
    timeout_seconds: int
    promotion_state: ToolPromotion = ToolPromotion.BUILTIN
