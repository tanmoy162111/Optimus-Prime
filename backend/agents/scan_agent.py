"""ScanAgent — Vulnerability scanning sub-agent (Section 5.2).

Tools: nikto, nuclei, masscan, wpscan
Follows recon phase — scans discovered services for vulnerabilities.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent
from backend.core.llm_router import LLMMessage, LLMRouter
from backend.core.models import AgentResult, AgentTask, AgentType, EngineType, Finding, FindingClassification

logger = logging.getLogger(__name__)

SCAN_SYSTEM_PROMPT = """You are a vulnerability scanning agent. Your goal is to find vulnerabilities on the target.

Available tools: nmap, nikto, nuclei, masscan, wpscan

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Scanning complete", "is_terminal": true}"""


@dataclass
class ScanAgent(BaseAgent):
    """Vulnerability scanning agent."""

    agent_type: AgentType = AgentType.SCAN
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"nmap", "nikto", "nuclei", "masscan", "wpscan"})
    )
    max_iterations: int = 20
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt, scope=self.scope)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, SCAN_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("nmap", {"target": target, "flags": "-sV -sC --top-ports 1000"}, "Service version and script scan"),
            AgentAction("nikto", {"target": target}, "Web server vulnerability scan"),
            AgentAction("nuclei", {"target": target, "flags": "-t cves/"}, "CVE template scan"),
            AgentAction("masscan", {"target": target, "flags": "-p1-65535 --rate=1000"}, "Fast full port scan"),
            AgentAction("wpscan", {"target": target, "flags": "--enumerate vp"}, "WordPress vulnerability scan"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action

    def parse_findings_from_output(self, tool_name: str, output: Any) -> list:
        """Parse scan tool output into structured findings."""
        import re
        findings = []
        if not output:
            return findings
        # KaliSSH backend returns a dict with 'stdout' — extract the actual
        # tool output rather than stringifying the whole dict (which escapes
        # newlines to \\n and corrupts multi-line regex matching).
        if isinstance(output, dict):
            output_str = output.get("stdout", "") or str(output)
        else:
            output_str = str(output)

        # nmap: open ports
        if tool_name == "nmap" and "open" in output_str.lower():
            for port, service in re.findall(r'(\d+)/(?:tcp|udp)\s+open\s+(\S+)', output_str):
                findings.append({
                    "finding_id": f"scan-{tool_name}-{port}",
                    "title": f"Open port {port}/{service}",
                    "severity": "info",
                    "tool": tool_name,
                })

        # nikto: vulnerability lines
        if tool_name == "nikto":
            for vuln_line in re.findall(r'\+ (OSVDB-\d+:.*)', output_str):
                findings.append({
                    "finding_id": f"scan-nikto-{hash(vuln_line) & 0xFFFF:04x}",
                    "title": vuln_line[:120],
                    "severity": "medium",
                    "tool": tool_name,
                })

        # nuclei: matched templates
        if tool_name == "nuclei":
            for match in re.findall(r'\[(\w+)\]\s+\[([^\]]+)\].*?(\S+)$', output_str, re.MULTILINE):
                severity, template_id, target = match
                findings.append({
                    "finding_id": f"scan-nuclei-{template_id}",
                    "title": f"Nuclei: {template_id}",
                    "severity": severity.lower(),
                    "tool": tool_name,
                })

        return findings


# Shared helpers used by all agents

def _extract_target(prompt: str, scope=None) -> str:
    """Extract a target IP/domain from the prompt text.

    Falls back to the first scope target when no IP/domain is found
    in the prompt, instead of returning the raw prompt string.
    """
    import re
    ip = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b', prompt)
    if ip:
        return ip.group()
    domain = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', prompt)
    if domain:
        return domain.group()
    # Fallback: use first target from scope config
    if scope and hasattr(scope, 'targets') and scope.targets:
        return scope.targets[0]
    return prompt.strip()


def _extract_json_from_llm_response(content: str, agent_name: str) -> dict:
    """Extract a JSON object from an LLM response that may contain prose or markdown.

    Tries strategies in order:
      1. Direct JSON parse (clean response).
      2. Extract from ```json ... ``` or ``` ... ``` code block.
      3. Grab the first {...} substring (ignoring surrounding prose).
      4. Strip single-quote wrapper and retry.
      5. Return safe default — is_terminal=False, tool=None — so the agent
         loop continues to its fallback planner rather than crashing.

    Never raises JSONDecodeError. Always returns a dict.
    """
    import re as _re

    content = (content or "").strip()

    if not content:
        return {"tool": None, "input": {}, "reasoning": "Empty LLM response", "is_terminal": False}

    # Strategy 1: direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Strategy 2: code block
    block_match = _re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, _re.DOTALL)
    if block_match:
        try:
            return json.loads(block_match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: first {...} substring (handles prose before/after JSON)
    brace_match = _re.search(r'\{.*\}', content, _re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # Strategy 4: single-quote wrapper (some LLMs wrap with single quotes)
    stripped = content.strip("'")
    if stripped != content:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
        # Try replacing single quotes with double quotes (non-standard LLM output)
        try:
            import ast
            parsed = ast.literal_eval(stripped)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, SyntaxError):
            pass

    # Strategy 5: safe default — agent loop continues via _plan_fallback
    logger.warning(
        "_extract_json_from_llm_response (%s): no valid JSON found — returning safe default. "
        "Response (first 200 chars): %.200s",
        agent_name, content,
    )
    return {
        "tool": None,
        "input": {},
        "reasoning": "LLM response could not be parsed as JSON — using fallback planner",
        "is_terminal": False,
    }


async def _plan_with_llm(agent, task, target, system_prompt) -> AgentAction | None:
    history = "\n".join(
        f"{i+1}. {a['tool']}({a['input']})" for i, a in enumerate(agent._action_history)
    ) or "None"
    try:
        response = await agent.llm_router.complete(
            messages=[LLMMessage(role="user", content=f"Target: {target}\nTask: {task.prompt}\nHistory:\n{history}")],
            system_prompt=system_prompt, max_tokens=512, temperature=0.3,
        )
    except Exception as exc:
        logger.warning("LLM planning call failed (%s), falling back to deterministic plan", exc)
        if hasattr(agent, '_plan_fallback'):
            return agent._plan_fallback(target)
        return None
    try:
        data = _extract_json_from_llm_response(response.content, agent.__class__.__name__)
    except json.JSONDecodeError:
        if hasattr(agent, '_plan_fallback'):
            return agent._plan_fallback(target)
        return None
    if data.get("is_terminal") or data.get("tool") is None:
        return None
    tool_input = data.get("input", {})
    if "target" not in tool_input:
        tool_input["target"] = target
    action = AgentAction(data["tool"], tool_input, data.get("reasoning", "LLM"))
    agent._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
    return action
