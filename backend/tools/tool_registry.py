"""ToolRegistry — Central registry of all built-in tool specifications (Section 5.2)."""

from __future__ import annotations

from backend.core.models import EngineType, PermissionMode, StealthLevel, StealthProfile, ToolBackendType
from backend.tools.tool_spec import ToolSpec, get_tool_timeout


def _make_spec(
    name: str,
    description: str,
    backend: ToolBackendType,
    engines: tuple[EngineType, ...],
    permission: PermissionMode = PermissionMode.EXECUTE,
    min_stealth: StealthLevel = StealthLevel.LOW,
    passive: bool = False,
) -> ToolSpec:
    """Helper to create a ToolSpec with defaults."""
    return ToolSpec(
        name=name,
        description=description,
        input_schema={},
        required_permission=permission,
        backend=backend,
        stealth_profile=StealthProfile(
            min_stealth_level=min_stealth,
            passive_only=passive,
        ),
        engine_scope=engines,
        timeout_seconds=get_tool_timeout(name),
    )


E1 = (EngineType.INFRASTRUCTURE,)
E3 = (EngineType.MLAI,)
E2 = (EngineType.ICS,)
KALI = ToolBackendType.KALI_SSH
ML = ToolBackendType.ML_RUNTIME_IPC
ICS = ToolBackendType.ICS_RUNTIME_IPC
TOR = ToolBackendType.TOR_SOCKS5
LOCAL = ToolBackendType.LOCAL


# All built-in tools per the agent registry (Section 5.2)
BUILTIN_TOOLS: dict[str, ToolSpec] = {}

_TOOL_DEFS: list[tuple] = [
    # ReconAgent
    ("nmap", "Network mapper — port scanning and service detection", KALI, E1),
    ("whatweb", "Web technology fingerprinting", KALI, E1),
    ("dnsrecon", "DNS enumeration and reconnaissance", KALI, E1),
    ("sublist3r", "Subdomain enumeration", KALI, E1),
    ("amass", "Attack surface mapping and asset discovery", KALI, E1),
    # ScanAgent
    ("nikto", "Web server vulnerability scanner", KALI, E1),
    ("nuclei", "Template-based vulnerability scanner", KALI, E1),
    ("masscan", "High-speed port scanner", KALI, E1),
    ("wpscan", "WordPress vulnerability scanner", KALI, E1),
    # ExploitAgent
    ("sqlmap", "SQL injection detection and exploitation", KALI, E1),
    ("dalfox", "XSS vulnerability scanner", KALI, E1),
    ("commix", "Command injection exploitation", KALI, E1),
    ("ffuf", "Web fuzzer", KALI, E1),
    ("msfconsole", "Metasploit framework", KALI, E1),
    ("payload_crafter", "Custom payload generation", KALI, E1),
    # IntelAgent
    ("shodan", "Internet-connected device search", KALI, E1),
    ("cve_search", "CVE database query", KALI, E1),
    ("exploit_db", "Exploit database query", KALI, E1),
    ("dark_web_query", "Dark web intelligence query", TOR, E1),
    # CloudAgent
    ("scoutsuite", "Multi-cloud security auditing", KALI, E1),
    ("prowler", "AWS security best practices assessment", KALI, E1),
    ("pacu", "AWS exploitation framework", KALI, E1),
    # IAMAgent
    ("jwt_tool", "JWT analysis and attack tool", KALI, E1),
    ("oauthscan", "OAuth2 vulnerability scanner", KALI, E1),
    ("saml_raider", "SAML security testing", KALI, E1),
    ("modlishka", "Reverse proxy phishing framework", KALI, E1),
    ("o365spray", "Microsoft 365 credential testing", KALI, E1),
    # DataSecAgent
    ("trufflehog", "Secret scanning in git repos", KALI, E1),
    ("gitleaks", "Git repository secret scanner", KALI, E1),
    ("testssl", "TLS/SSL configuration testing", KALI, E1),
    ("pii_parser", "PII detection in data", KALI, E1),
    ("exfil_sim", "Data exfiltration simulation", KALI, E1),
    # EndpointAgent
    ("sharp_edr_checker", "EDR detection and evasion", KALI, E1),
    ("lotl_crafter", "Living off the land technique builder", KALI, E1),
    # ScopeDiscoveryAgent
    ("crt_sh", "Certificate transparency log search", KALI, E1),
    ("whois", "Domain registration lookup", KALI, E1),
    ("dns_enum", "DNS enumeration", KALI, E1),
    ("github_scan", "GitHub repository scanning", KALI, E1),
    # ModelSecAgent (Engine 3)
    ("art_fgsm", "FGSM adversarial attack", ML, E3),
    ("art_pgd", "PGD adversarial attack", ML, E3),
    ("art_cw", "Carlini-Wagner adversarial attack", ML, E3),
    ("model_extract", "Model extraction via query budget", ML, E3),
    ("membership_infer", "Membership inference attack", ML, E3),
    ("model_audit", "Static model security audit", ML, E3),
    # GenAIAgent (Engine 3)
    ("promptfoo", "LLM prompt injection testing", ML, E3),
    ("canary_inject", "Canary token injection test", ML, E3),
    ("rag_poison", "RAG poisoning test", ML, E3),
    ("agent_hijack", "Agent hijacking test", ML, E3),
    # ICSAgent (Engine 2)
    ("plcscan", "PLC discovery and fingerprinting", ICS, E2),
    ("modbus_read", "Modbus register read (non-destructive)", ICS, E2),
    ("dnp3_probe", "DNP3 protocol enumeration", ICS, E2),
    ("ics_fingerprint", "ICS device fingerprinting", ICS, E2),
    # Verification tools
    ("curl", "HTTP GET request (verification only)", LOCAL, E1),
    ("nmap_verify", "Targeted port verification scan", KALI, E1),
    ("testssl_readonly", "TLS verification (read-only mode)", KALI, E1),
    ("httpx_probe", "HTTP probe (verification only)", LOCAL, E1),
]

for _name, _desc, _backend, _engines in _TOOL_DEFS:
    BUILTIN_TOOLS[_name] = _make_spec(_name, _desc, _backend, _engines)


class ToolRegistry:
    """Central tool registry. Manages built-in and custom tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = dict(BUILTIN_TOOLS)

    def get(self, name: str) -> ToolSpec | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    def register(self, spec: ToolSpec) -> None:
        """Register a new tool (e.g., custom generated tool)."""
        self._tools[spec.name] = spec

    def list_tools(self, engine: EngineType | None = None) -> list[ToolSpec]:
        """List all tools, optionally filtered by engine."""
        if engine is None:
            return list(self._tools.values())
        return [t for t in self._tools.values() if engine in t.engine_scope]

    def as_dict(self) -> dict[str, ToolSpec]:
        """Return the full registry as a dict."""
        return dict(self._tools)
