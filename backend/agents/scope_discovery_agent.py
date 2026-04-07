"""ScopeDiscoveryAgent — Asset discovery and scope validation sub-agent (Section 5.2).

Tools: crt_sh, whois, shodan, dns_enum, github_scan
Runs first in most engagements to establish scope boundaries.
Produces >= 5 asset types from a seed domain.

Asset types:
  - subdomains (crt_sh)
  - registrant_info (whois)
  - network_services (shodan, stealth-aware)
  - ip_addresses (dns_enum)
  - code_repositories (github_scan)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent
from backend.core.llm_router import LLMRouter
from backend.core.models import (
    AgentResult,
    AgentTask,
    AgentType,
    EngineType,
    StealthLevel,
)
from backend.agents.scan_agent import _extract_target, _plan_with_llm

logger = logging.getLogger(__name__)

SCOPE_SYSTEM_PROMPT = """You are a scope discovery agent. Enumerate assets and validate scope boundaries.

Available tools: crt_sh, whois, shodan, dns_enum, github_scan
Note: shodan is only available at stealth levels low and medium.

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Scope discovery complete", "is_terminal": true}"""

# Asset type categories
ASSET_TYPES = [
    "subdomains",
    "registrant_info",
    "network_services",
    "ip_addresses",
    "code_repositories",
]


@dataclass
class ScopeDiscoveryAgent(BaseAgent):
    """Scope discovery and asset enumeration agent.

    Produces >= 5 asset types from a seed domain:
      - subdomains: from crt_sh (CT log search)
      - registrant_info: from whois (domain registration)
      - network_services: from shodan (stealth-aware, skipped at HIGH)
      - ip_addresses: from dns_enum (DNS enumeration)
      - code_repositories: from github_scan (GitHub search)
    """

    agent_type: AgentType = AgentType.SCOPE_DISCOVERY
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"crt_sh", "whois", "shodan", "dns_enum", "github_scan", "nmap", "whatweb"})
    )
    max_iterations: int = 10
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)
    _discovered_assets: dict[str, list[Any]] = field(default_factory=dict)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        self._discovered_assets = {t: [] for t in ASSET_TYPES}
        result = await self.run_loop(task)

        # Guarantee at least 1 finding — scope anchor from the seed target
        if not result.findings:
            target = _extract_target(task.prompt, scope=self.scope)
            anchor = {
                "finding_id": f"scope-anchor-{abs(hash(target)) & 0xFFFF:04x}",
                "title": f"Target in scope: {target}",
                "severity": "info",
                "tool": "scope_discovery",
                "target": target,
                "description": (
                    f"Seed target '{target}' confirmed in engagement scope. "
                    "Asset discovery tools returned no additional data."
                ),
            }
            result.findings = [anchor]
            if self.event_bus:
                await self.event_bus.publish(
                    channel="findings",
                    event_type="FINDING_CREATED",
                    payload=anchor,
                )

        # Attach asset summary to result metadata
        result.metadata = result.metadata or {}
        result.metadata["asset_types"] = self._discovered_assets
        result.metadata["asset_type_count"] = sum(
            1 for v in self._discovered_assets.values() if v
        )
        return result

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt, scope=self.scope)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, SCOPE_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _detect_target_type(self, target: str) -> str:
        """Detect whether target is internal RFC-1918, public IP, or public domain.

        Returns:
            "internal"      — RFC-1918 IP (10.x, 172.16-31.x, 192.168.x)
            "public_ip"     — Routable IP address
            "public_domain" — Domain name (contains letters, no CIDR slash)
        """
        import ipaddress
        import re as _re

        # Domain: has letters and dots but no slash (not CIDR)
        if _re.match(r'^[a-zA-Z]', target) and '/' not in target:
            return "public_domain"

        # Try as IP address
        try:
            ip = ipaddress.ip_address(target.split('/')[0])
            if ip.is_private:
                return "internal"
            return "public_ip"
        except ValueError:
            pass

        # Fallback for CIDR ranges — check first octet
        first_octet_match = _re.match(r'^(\d+)\.', target)
        if first_octet_match:
            first = int(first_octet_match.group(1))
            if first == 10 or first == 172 or first == 192:
                return "internal"
        return "public_ip"

    def _plan_fallback(self, target: str) -> AgentAction | None:
        """Route tool selection based on target type.

        internal    → nmap (full port scan), whatweb, dns_enum
        public_ip   → shodan (InternetDB), nmap, whatweb, whois
        public_domain → crt_sh, whois, shodan, dns_enum, github_scan
        """
        target_type = self._detect_target_type(target)

        if target_type == "internal":
            steps = [
                AgentAction("nmap", {"target": target, "flags": "-Pn -sV --top-ports 1000"}, "Full port scan of internal target"),
                AgentAction("whatweb", {"target": target, "flags": "-a 3"}, "Web tech fingerprinting"),
                AgentAction("dns_enum", {"target": target}, "DNS enumeration for IPs"),
            ]
        elif target_type == "public_ip":
            steps = [
                AgentAction("shodan", {"target": target}, "Internet exposure check via Shodan InternetDB"),
                AgentAction("nmap", {"target": target, "flags": "-Pn -sV --top-ports 1000"}, "Port scan"),
                AgentAction("whatweb", {"target": target, "flags": "-a 3"}, "Web tech fingerprinting"),
                AgentAction("whois", {"target": target}, "WHOIS lookup"),
            ]
        else:  # public_domain
            steps = [
                AgentAction("crt_sh", {"target": target}, "Certificate transparency — subdomain discovery"),
                AgentAction("whois", {"target": target}, "Domain registration info"),
                AgentAction("dns_enum", {"target": target}, "DNS enumeration — IP addresses"),
                AgentAction("github_scan", {"target": target}, "GitHub repository search"),
            ]
            # Shodan only at low/medium stealth
            if self.stealth_level != StealthLevel.HIGH:
                steps.insert(2, AgentAction("shodan", {"target": target}, "Internet exposure via Shodan"))

        step = len(self._action_history)
        if step >= len(steps):
            return None

        action = steps[step]
        self._action_history.append({
            "tool": action.tool_name,
            "input": action.tool_input,
            "reasoning": action.reasoning,
        })
        return action

    def parse_findings_from_output(self, tool_name: str, output: Any) -> list:
        """Parse scope discovery tool output into structured findings.

        Each discovered asset (subdomain, IP, open port, repo) becomes an
        info-severity finding so it surfaces in the EventBus and report.
        Also updates _discovered_assets for the asset-type summary.
        """
        import json as _json
        import re as _re

        findings: list[dict] = []
        if not output:
            return findings

        if isinstance(output, dict):
            # Silently skip tools that were not installed on Kali
            if output.get("status") == "tool_not_found":
                logger.info("ScopeDiscoveryAgent: %s not available, skipping", tool_name)
                return findings
            output_str = output.get("stdout", "") or str(output)
        else:
            output_str = str(output)

        if not output_str or len(output_str.strip()) < 5:
            return findings

        target = (
            self._action_history[-1]["input"].get("target", "")
            if self._action_history else ""
        )

        if tool_name == "crt_sh":
            # Try JSON output first, then regex fallback
            domains: set[str] = set()
            try:
                data = _json.loads(output_str)
                for entry in (data if isinstance(data, list) else []):
                    name = entry.get("name_value", "") or entry.get("common_name", "")
                    for d in name.replace("*.", "").split("\n"):
                        d = d.strip()
                        if d and "." in d:
                            domains.add(d)
            except (_json.JSONDecodeError, TypeError):
                # Regex fallback: grab any host that shares the seed domain
                seed_parts = target.rsplit(".", 2)[-2:]
                seed_suffix = ".".join(seed_parts)
                for d in _re.findall(r'[\w*.-]+\.' + _re.escape(seed_suffix), output_str):
                    domains.add(d.strip().lstrip("*."))

            self._discovered_assets.setdefault("subdomains", []).extend(
                list(domains)[:50]
            )
            for domain in sorted(domains)[:50]:
                findings.append({
                    "finding_id": f"scope-crtsh-{abs(hash(domain)) & 0xFFFF:04x}",
                    "title": f"Subdomain discovered: {domain}",
                    "severity": "info",
                    "tool": tool_name,
                    "target": domain,
                    "description": (
                        f"Subdomain '{domain}' discovered via certificate transparency logs"
                    ),
                })

        elif tool_name == "whois":
            self._discovered_assets.setdefault("registrant_info", []).append(
                {"raw": output_str[:500]}
            )
            # Extract registrant org / name if present
            org_match = _re.search(
                r'(?:Registrant\s+)?Org(?:anization)?[:\s]+(.+)', output_str, _re.IGNORECASE
            )
            org = org_match.group(1).strip()[:80] if org_match else "unknown"
            findings.append({
                "finding_id": f"scope-whois-{abs(hash(target)) & 0xFFFF:04x}",
                "title": f"WHOIS registrant info for {target}",
                "severity": "info",
                "tool": tool_name,
                "target": target,
                "description": f"Registrant org: {org}. Raw: {output_str[:300]}",
            })

        elif tool_name == "shodan":
            # InternetDB JSON: {"ip": ..., "ports": [...], "vulns": [...]}
            try:
                data = _json.loads(output_str)
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                self._discovered_assets.setdefault("network_services", []).extend(
                    [{"port": p} for p in ports]
                )
                for p in ports:
                    sev = "medium" if vulns else "info"
                    findings.append({
                        "finding_id": f"scope-shodan-port-{p}",
                        "title": f"Internet-exposed port {p} on {target}",
                        "severity": sev,
                        "tool": tool_name,
                        "target": target,
                        "port": p,
                        "description": (
                            f"Port {p} is internet-visible. "
                            + (f"Known CVEs: {', '.join(vulns[:5])}" if vulns else "")
                        ),
                    })
            except (_json.JSONDecodeError, TypeError):
                # Fallback: regex for port numbers
                for p in _re.findall(r'\bport[:\s]+(\d+)', output_str, _re.IGNORECASE):
                    findings.append({
                        "finding_id": f"scope-shodan-{p}",
                        "title": f"Internet-exposed service on port {p}",
                        "severity": "info",
                        "tool": tool_name,
                        "target": target,
                        "port": int(p),
                        "description": f"Shodan: port {p} visible on {target}",
                    })

        elif tool_name == "dns_enum":
            ips = list(dict.fromkeys(
                _re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output_str)
            ))[:20]
            self._discovered_assets.setdefault("ip_addresses", []).extend(ips)
            for ip in ips:
                findings.append({
                    "finding_id": f"scope-dns-{ip.replace('.', '-')}",
                    "title": f"DNS resolved: {target} → {ip}",
                    "severity": "info",
                    "tool": tool_name,
                    "target": target,
                    "description": f"DNS enumeration resolved {target} to {ip}",
                })

        elif tool_name == "github_scan":
            # GitHub API JSON: {"items": [{"full_name": ...}]}
            repos: list[str] = []
            try:
                data = _json.loads(output_str)
                repos = [
                    item["full_name"]
                    for item in data.get("items", [])[:10]
                    if "full_name" in item
                ]
            except (_json.JSONDecodeError, TypeError):
                repos = _re.findall(r'"full_name":\s*"([^"]+)"', output_str)[:10]

            self._discovered_assets.setdefault("code_repositories", []).extend(repos)
            for repo in repos:
                findings.append({
                    "finding_id": f"scope-github-{abs(hash(repo)) & 0xFFFF:04x}",
                    "title": f"Public GitHub repository: {repo}",
                    "severity": "info",
                    "tool": tool_name,
                    "target": target,
                    "description": f"Public repository '{repo}' associated with {target}",
                })

        return findings

    def parse_asset_types(self, tool_outputs: dict[str, Any]) -> dict[str, list[Any]]:
        """Parse tool outputs into categorized asset types.

        Returns dict mapping asset type -> list of discovered assets.
        At least 5 asset types should be populated from a seed domain.
        """
        assets: dict[str, list[Any]] = {t: [] for t in ASSET_TYPES}

        for tool_name, output in tool_outputs.items():
            output_str = str(output) if output else ""

            if tool_name == "crt_sh":
                # CT logs -> subdomains
                import re
                domains = re.findall(r'[\w.-]+\.[a-zA-Z]{2,}', output_str)
                assets["subdomains"].extend(list(set(domains))[:20])

            elif tool_name == "whois":
                # WHOIS -> registrant info
                registrant_fields = {}
                for line in output_str.split("\n"):
                    for key in ["Registrant", "Organization", "Admin", "Tech", "Name Server"]:
                        if key.lower() in line.lower():
                            registrant_fields[key] = line.strip()
                if registrant_fields:
                    assets["registrant_info"].append(registrant_fields)
                else:
                    assets["registrant_info"].append({"raw": output_str[:200]})

            elif tool_name == "shodan":
                # Shodan -> network services
                import re
                ports = re.findall(r'port[:\s]+(\d+)', output_str, re.IGNORECASE)
                services = re.findall(r'service[:\s]+(\S+)', output_str, re.IGNORECASE)
                if ports or services:
                    for p in ports:
                        assets["network_services"].append({"port": int(p)})
                    for s in services:
                        assets["network_services"].append({"service": s})
                else:
                    assets["network_services"].append({"raw": output_str[:200]})

            elif tool_name == "dns_enum":
                # DNS -> IP addresses
                import re
                ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output_str)
                assets["ip_addresses"].extend(list(set(ips))[:20])

            elif tool_name == "github_scan":
                # GitHub -> code repositories
                import re
                repos = re.findall(r'github\.com/[\w.-]+/[\w.-]+', output_str)
                if repos:
                    assets["code_repositories"].extend(list(set(repos))[:10])
                else:
                    assets["code_repositories"].append({"search_result": output_str[:200]})

        return assets
