"""ToolFallbackResolver — Multi-strategy tool failure recovery (Section 3.4).

When an agent tool returns tool_not_found or command_error, this resolver
tries recovery strategies in priority order:
  1. Alternative tool table (no cost, instant)
  2. Pattern-based command correction (no cost, instant)
  3. Auto-install via apt-get/pip (requires kali_mgr, ~120s max)
  4. LLM command correction (requires llm_router)
  5. ResearchKB query (requires research_kb)
  6. Live web query via Kali curl (requires kali_mgr)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Alternative tool mapping: tool_name → [alternatives in priority order]
# -------------------------------------------------------------------
TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "sublist3r":       ["amass", "dnsrecon"],
    "amass":           ["sublist3r", "dnsrecon"],
    "dalfox":          ["nuclei"],
    "masscan":         ["nmap"],
    "wpscan":          ["nikto", "nuclei"],
    "commix":          ["sqlmap"],
    "payload_crafter": ["msfvenom"],
    "dnsrecon":        ["dns_enum"],
    "whatweb":         ["curl"],
    "github_scan":     [],   # OSINT only, no local alternative
    "crt_sh":          [],   # OSINT only, no local alternative
}

# Alternative tool input transformations
_ALT_INPUT_TRANSFORMS: dict[tuple[str, str], dict] = {
    # (original_tool, alternative_tool) → override input keys
    ("dalfox", "nuclei"):  {"flags": "-t cves/ -t exposures/"},
    ("masscan", "nmap"):   {"flags": "-T4 -p-"},
    ("wpscan", "nikto"):   {},
    ("dnsrecon", "dns_enum"): {},
}

# -------------------------------------------------------------------
# Pattern-based command fixes
# -------------------------------------------------------------------
_COMMAND_FIXES: dict[str, dict[str, str]] = {
    "masscan":    {"add_flag": "--rate=500", "missing_flag": "--rate"},
    "nuclei":     {"add_flag": "-t cves/",   "missing_flag": "-t "},
    "msfconsole": {"add_flag": "-q",          "missing_flag": "-q"},
    "ffuf":       {"add_flag": "-mc 200,301,302", "missing_flag": "-mc"},
    "sqlmap":     {"add_flag": "--batch",     "missing_flag": "--batch"},
    "nikto":      {"add_flag": "-maxtime 90", "missing_flag": "-maxtime"},
}

# apt-get package names for tools (may differ from binary name)
_APT_PACKAGES: dict[str, str] = {
    "sublist3r":  "sublist3r",
    "amass":      "amass",
    "dalfox":     "dalfox",
    "masscan":    "masscan",
    "wpscan":     "wpscan",
    "commix":     "commix",
    "nikto":      "nikto",
    "nuclei":     "nuclei",
    "ffuf":       "ffuf",
    "sqlmap":     "sqlmap",
    "whatweb":    "whatweb",
    "dnsrecon":   "dnsrecon",
}


@dataclass
class FallbackResolution:
    """Result of a ToolFallbackResolver.resolve() call."""
    alternative_tool: str | None = None
    alternative_input: dict[str, Any] | None = None
    corrected_flags: str | None = None    # corrected flags for original tool
    install_succeeded: bool = False
    skip: bool = False                    # no resolution — caller should skip this tool


class ToolFallbackResolver:
    """Multi-strategy recovery for tool_not_found and command errors.

    Instantiate with optional kali_mgr, llm_router, research_kb for
    strategies that need them. Strategies that lack their dependency
    are skipped automatically.
    """

    def __init__(
        self,
        kali_mgr: Any = None,
        llm_router: Any = None,
        research_kb: Any = None,
    ) -> None:
        self._kali_mgr = kali_mgr
        self._llm_router = llm_router
        self._research_kb = research_kb

    async def resolve(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        error: str,
        error_type: str = "tool_not_found",  # "tool_not_found" | "command_error"
        tried_tools: set[str] | None = None,
    ) -> FallbackResolution:
        """Attempt to recover from a tool failure.

        Args:
            tool_name: The tool that failed.
            tool_input: The input dict that was passed to the tool.
            error: The error string from the failure.
            error_type: "tool_not_found" or "command_error".
            tried_tools: Set of tool names already tried (avoid retry loops).

        Returns:
            FallbackResolution with the best available recovery.
        """
        tried = tried_tools or set()
        tried.add(tool_name)

        # Strategy 1: Alternative tool table
        resolution = self._try_alternative(tool_name, tool_input, tried)
        if resolution:
            logger.info("ToolFallbackResolver: %s → alternative %s", tool_name, resolution.alternative_tool)
            return resolution

        # Strategy 2: Pattern-based command correction (for command_error only)
        if error_type == "command_error":
            resolution = self._try_pattern_fix(tool_name, tool_input)
            if resolution:
                logger.info("ToolFallbackResolver: %s — applied pattern fix", tool_name)
                return resolution

        # Strategy 3: Auto-install
        if self._kali_mgr:
            installed = await self._try_install(tool_name)
            if installed:
                return FallbackResolution(install_succeeded=True)

        # Strategy 4: LLM command correction
        if self._llm_router and error_type == "command_error":
            resolution = await self._try_llm_correction(tool_name, tool_input, error)
            if resolution:
                logger.info("ToolFallbackResolver: %s — LLM suggested correction", tool_name)
                return resolution

        # Strategy 5: ResearchKB query
        if self._research_kb:
            resolution = await self._try_research_kb(tool_name, error)
            if resolution:
                return resolution

        # Strategy 6: Live web query via Kali
        if self._kali_mgr:
            resolution = await self._try_live_web_query(tool_name)
            if resolution:
                return resolution

        logger.warning("ToolFallbackResolver: no recovery found for %s — skipping", tool_name)
        return FallbackResolution(skip=True)

    def _try_alternative(
        self, tool_name: str, tool_input: dict[str, Any], tried: set[str]
    ) -> FallbackResolution | None:
        alternatives = TOOL_ALTERNATIVES.get(tool_name, [])
        for alt in alternatives:
            if alt not in tried:
                # Build alternative input: start with original, apply transform
                alt_input = dict(tool_input)
                transform = _ALT_INPUT_TRANSFORMS.get((tool_name, alt), {})
                alt_input.update(transform)
                return FallbackResolution(alternative_tool=alt, alternative_input=alt_input)
        return None

    def _try_pattern_fix(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> FallbackResolution | None:
        fix = _COMMAND_FIXES.get(tool_name)
        if not fix:
            return None
        current_flags = tool_input.get("flags", "")
        if fix["missing_flag"] not in current_flags:
            corrected = (current_flags + " " + fix["add_flag"]).strip()
            return FallbackResolution(corrected_flags=corrected)
        return None

    async def _try_install(self, tool_name: str) -> bool:
        """Attempt apt-get install for the missing tool. Returns True on success."""
        package = _APT_PACKAGES.get(tool_name, tool_name)
        try:
            result = await self._kali_mgr.execute(
                tool_name="_install",
                tool_input={"command": f"apt-get install -y -q {package} 2>/dev/null || pip3 install {package} 2>/dev/null"},
                tool_spec=_MinimalToolSpec(timeout_seconds=120),
            )
            success = result.get("exit_code", 1) == 0
            if success:
                logger.info("ToolFallbackResolver: installed %s via apt-get", package)
            else:
                logger.warning("ToolFallbackResolver: install failed for %s", package)
            return success
        except Exception as exc:
            logger.warning("ToolFallbackResolver: install error for %s: %s", tool_name, exc)
            return False

    async def _try_llm_correction(
        self, tool_name: str, tool_input: dict[str, Any], error: str
    ) -> FallbackResolution | None:
        from backend.core.llm_router import LLMMessage
        try:
            prompt = (
                f"This command failed on Kali Linux: `{tool_name} {tool_input.get('flags', '')} "
                f"{tool_input.get('target', '')}`\n"
                f"Error: {error[:200]}\n"
                f"Suggest corrected flags only (not the full command). Return just the flags string."
            )
            response = await self._llm_router.complete(
                messages=[LLMMessage(role="user", content=prompt)],
                system_prompt="You are a Kali Linux expert. Return only corrected CLI flags, no explanation.",
                max_tokens=128,
                temperature=0.1,
            )
            corrected = response.content.strip().strip("`")
            if corrected and len(corrected) < 200:
                return FallbackResolution(corrected_flags=corrected)
        except Exception as exc:
            logger.debug("ToolFallbackResolver: LLM correction failed: %s", exc)
        return None

    async def _try_research_kb(
        self, tool_name: str, error: str
    ) -> FallbackResolution | None:
        """Query ResearchKB for known tool issues and fixes."""
        try:
            entries = await self._research_kb.query(keyword=tool_name, limit=3)
            for entry in entries:
                desc = entry.description.lower()
                if "install" in desc or "alternative" in desc:
                    logger.info(
                        "ToolFallbackResolver: ResearchKB found hint for %s", tool_name
                    )
                    # ResearchKB hit but no actionable fix — at minimum log it
                    break
        except Exception as exc:
            logger.debug("ToolFallbackResolver: ResearchKB query failed: %s", exc)
        return None  # ResearchKB provides context, not direct action in v1

    async def _try_live_web_query(self, tool_name: str) -> FallbackResolution | None:
        """Query live web via Kali curl for tool install hints."""
        try:
            result = await self._kali_mgr.execute(
                tool_name="_web_query",
                tool_input={
                    "command": (
                        f"timeout 10 curl -s 'https://api.github.com/search/repositories"
                        f"?q={tool_name}+kali+linux&per_page=1' 2>/dev/null | "
                        f"python3 -c \"import sys,json; d=json.load(sys.stdin); "
                        f"[print(i.get('html_url','')) for i in d.get('items',[])[:1]]\" 2>/dev/null"
                    )
                },
                tool_spec=_MinimalToolSpec(timeout_seconds=15),
            )
            stdout = result.get("stdout", "").strip()
            if stdout:
                logger.info(
                    "ToolFallbackResolver: live web query for %s found: %s", tool_name, stdout[:100]
                )
        except Exception as exc:
            logger.debug("ToolFallbackResolver: live web query failed: %s", exc)
        return None  # Web query provides context, not direct action in v1


class _MinimalToolSpec:
    """Minimal tool spec for install/query commands that bypass the registry."""
    def __init__(self, timeout_seconds: int = 60) -> None:
        self.timeout_seconds = timeout_seconds
