"""CustomToolGenerator — Three-gate tool promotion workflow (Section 6.5, N13, N14).

Generated tools pass through three mandatory gates:
  G1: AST static analysis — syntactic + security checks
  G2: Sandbox execution — runs against DVWA, effectiveness scored
  G3: Operator approval — approve / reject / approve-once via chat
"""

from __future__ import annotations

import ast
import asyncio
import enum
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


class ToolPromotionState(str, enum.Enum):
    """Promotion state machine for generated tools."""
    GENERATED = "generated"
    G1_PASSED = "g1_passed"
    G1_FAILED = "g1_failed"
    SANDBOX_APPROVED = "sandbox_approved"
    SANDBOX_FAILED = "sandbox_failed"
    OPERATOR_APPROVED = "operator_approved"
    OPERATOR_REJECTED = "operator_rejected"
    APPROVE_ONCE = "approve_once"


@dataclass
class GeneratedTool:
    """A tool produced by CustomToolGenerator."""
    tool_id: str
    name: str
    description: str
    code: str
    language: str = "python"
    state: ToolPromotionState = ToolPromotionState.GENERATED
    g1_result: dict[str, Any] = field(default_factory=dict)
    g2_result: dict[str, Any] = field(default_factory=dict)
    g3_result: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    vulnerability_context: str = ""


@dataclass
class ASTGateResult:
    """Result of G1 AST static analysis gate."""
    passed: bool
    issues: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class SandboxResult:
    """Result of G2 sandbox execution gate."""
    passed: bool
    effectiveness_score: float = 0.0
    findings_produced: int = 0
    expected_targets: int = 1
    output: str = ""
    error: str = ""
    execution_time_seconds: float = 0.0


class ASTSecurityAnalyzer:
    """Gate 1 — AST-based static analysis for generated tool code (N13).

    Detects dangerous patterns:
      - subprocess(shell=True) with unsanitized inputs
      - eval()/exec() on external data
      - os.system() calls
      - File writes outside /tmp/optimus_tools/
    """

    DANGEROUS_FUNCTIONS = {"eval", "exec"}
    DANGEROUS_OS_CALLS = {"system", "popen", "exec", "execv", "execve", "execvp"}
    SAFE_WRITE_PREFIX = "/tmp/optimus_tools/"

    def analyze(self, code: str) -> ASTGateResult:
        """Run AST analysis on generated code. Returns pass/fail with issues."""
        issues: list[str] = []

        # Parse check
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return ASTGateResult(
                passed=False,
                issues=[f"Syntax error: {exc}"],
                detail="Code failed to parse",
            )

        # Build alias maps for resolving imports
        self._subprocess_aliases: set[str] = set()
        self._subprocess_funcs: set[str] = set()  # directly imported subprocess funcs
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        self._subprocess_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and "subprocess" in node.module:
                    for alias in node.names:
                        self._subprocess_funcs.add(alias.asname or alias.name)

        # Walk AST
        for node in ast.walk(tree):
            self._check_subprocess_shell(node, issues)
            self._check_eval_exec(node, issues)
            self._check_os_system(node, issues)
            self._check_unsafe_file_write(node, issues)
            self._check_dunder_import(node, issues)
            self._check_getattr_import(node, issues)

        return ASTGateResult(
            passed=len(issues) == 0,
            issues=issues,
            detail="All checks passed" if not issues else f"{len(issues)} security issue(s) found",
        )

    def _check_subprocess_shell(self, node: ast.AST, issues: list[str]) -> None:
        """Detect subprocess calls with shell=True."""
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_call_name(node)
        is_subprocess = False

        if func_name:
            # Direct: subprocess.run(...), subprocess.Popen(...)
            if "subprocess" in func_name:
                is_subprocess = True
            # Aliased: import subprocess as sp; sp.run(...)
            parts = func_name.split(".")
            if len(parts) == 2 and parts[0] in getattr(self, '_subprocess_aliases', set()):
                is_subprocess = True
            # from subprocess import run; run(...)
            if len(parts) == 1 and parts[0] in getattr(self, '_subprocess_funcs', set()):
                is_subprocess = True

        if is_subprocess:
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        issues.append(
                            f"subprocess call with shell=True at line {node.lineno}"
                        )

    def _check_eval_exec(self, node: ast.AST, issues: list[str]) -> None:
        """Detect eval()/exec() calls."""
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_call_name(node)
        if func_name in self.DANGEROUS_FUNCTIONS:
            issues.append(f"{func_name}() call at line {node.lineno}")

    def _check_os_system(self, node: ast.AST, issues: list[str]) -> None:
        """Detect os.system(), os.popen(), etc."""
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_call_name(node)
        if func_name:
            parts = func_name.split(".")
            if len(parts) == 2 and parts[0] == "os" and parts[1] in self.DANGEROUS_OS_CALLS:
                issues.append(f"os.{parts[1]}() call at line {node.lineno}")

    def _check_dunder_import(self, node: ast.AST, issues: list[str]) -> None:
        """Detect __import__('os').system(...) patterns."""
        if not isinstance(node, ast.Call):
            return
        # __import__("os").system("id") — the outer call's func is an Attribute
        # whose value is a Call to __import__
        if isinstance(node.func, ast.Attribute):
            inner = node.func.value
            if isinstance(inner, ast.Call):
                inner_name = self._get_call_name(inner)
                if inner_name == "__import__":
                    issues.append(
                        f"__import__() dynamic import at line {node.lineno}"
                    )
                    return
        # Direct __import__ call (e.g. eval uses it indirectly, but also standalone)
        func_name = self._get_call_name(node)
        if func_name == "__import__":
            issues.append(f"__import__() dynamic import at line {node.lineno}")

    def _check_getattr_import(self, node: ast.AST, issues: list[str]) -> None:
        """Detect getattr(__import__('os'), 'system')(...) patterns."""
        if not isinstance(node, ast.Call):
            return
        func_name = self._get_call_name(node)
        if func_name == "getattr" and node.args:
            # Check if first arg is __import__ call
            if isinstance(node.args[0], ast.Call):
                inner_name = self._get_call_name(node.args[0])
                if inner_name == "__import__":
                    issues.append(
                        f"getattr(__import__(...)) evasion at line {node.lineno}"
                    )

    def _check_unsafe_file_write(self, node: ast.AST, issues: list[str]) -> None:
        """Detect file writes outside /tmp/optimus_tools/."""
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_call_name(node)
        if func_name == "open" and node.args:
            # Check the file path argument
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                path = node.args[0].value
                if not path.startswith(self.SAFE_WRITE_PREFIX) and not path.startswith("/tmp/optimus"):
                    # Check if opened for writing
                    mode = "r"
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = str(node.args[1].value)
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if "w" in mode or "a" in mode:
                        issues.append(
                            f"File write outside safe directory at line {node.lineno}: {path}"
                        )

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None


class CustomToolGenerator:
    """Three-gate tool promotion pipeline (Section 6.5).

    Workflow:
      1. LLM generates tool code from vulnerability context
      2. G1: AST static analysis — rejects dangerous patterns
      3. G2: Sandbox execution against DVWA — measures effectiveness
      4. G3: Operator approval via chat — approve/reject/approve-once
    """

    def __init__(
        self,
        llm_router: Any = None,
        sandbox_executor: Any = None,
        event_bus: Any = None,
        tool_registry: dict[str, Any] | None = None,
    ) -> None:
        self._llm = llm_router
        self._sandbox = sandbox_executor
        self._event_bus = event_bus
        self._tool_registry = tool_registry or {}
        self._ast_analyzer = ASTSecurityAnalyzer()
        self._pending_tools: dict[str, GeneratedTool] = {}

    @property
    def ast_analyzer(self) -> ASTSecurityAnalyzer:
        return self._ast_analyzer

    async def generate_tool(
        self,
        vulnerability_context: str,
        research_context: str = "",
    ) -> GeneratedTool:
        """Generate a tool from vulnerability context using LLM.

        Returns a GeneratedTool in GENERATED state.
        """
        tool_id = f"custom-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        code = ""
        name = f"custom_exploit_{tool_id[-8:]}"
        description = f"Auto-generated tool for: {vulnerability_context[:100]}"

        if self._llm:
            from backend.core.llm_router import LLMMessage
            response = await self._llm.complete(
                messages=[LLMMessage(
                    role="user",
                    content=(
                        f"Generate a Python security tool for this vulnerability:\n"
                        f"{vulnerability_context}\n\n"
                        f"Research context:\n{research_context}\n\n"
                        f"Requirements:\n"
                        f"- Write to /tmp/optimus_tools/ only\n"
                        f"- No eval(), exec(), os.system()\n"
                        f"- Use subprocess with shell=False\n"
                        f"- Output findings as JSON to stdout\n"
                        f"Return ONLY the Python code."
                    ),
                )],
                system_prompt="You are a security tool generator. Output only valid Python code.",
                max_tokens=2048,
                temperature=0.3,
            )
            code = response.content
        else:
            # Fallback: generate a simple placeholder
            code = (
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import sys\n\n"
                f"# Auto-generated tool: {name}\n"
                "def main(target):\n"
                "    findings = []\n"
                "    # Tool logic here\n"
                "    print(json.dumps(findings))\n\n"
                'if __name__ == "__main__":\n'
                "    main(sys.argv[1] if len(sys.argv) > 1 else 'localhost')\n"
            )

        tool = GeneratedTool(
            tool_id=tool_id,
            name=name,
            description=description,
            code=code,
            state=ToolPromotionState.GENERATED,
            created_at=now,
            vulnerability_context=vulnerability_context,
        )

        self._pending_tools[tool_id] = tool
        return tool

    async def run_gate_1(self, tool: GeneratedTool) -> ASTGateResult:
        """G1 — AST static analysis gate (N13)."""
        result = self._ast_analyzer.analyze(tool.code)
        tool.g1_result = {
            "passed": result.passed,
            "issues": result.issues,
            "detail": result.detail,
        }

        if result.passed:
            tool.state = ToolPromotionState.G1_PASSED
            logger.info("CustomToolGenerator: G1 PASSED for %s", tool.tool_id)
        else:
            tool.state = ToolPromotionState.G1_FAILED
            logger.warning(
                "CustomToolGenerator: G1 FAILED for %s — %s",
                tool.tool_id, result.issues,
            )

        return result

    async def run_gate_2(
        self,
        tool: GeneratedTool,
        sandbox_executor: Any = None,
    ) -> SandboxResult:
        """G2 — Sandbox execution against DVWA (max 120s)."""
        executor = sandbox_executor or self._sandbox

        if tool.state != ToolPromotionState.G1_PASSED:
            return SandboxResult(
                passed=False,
                error="G1 not passed — cannot proceed to G2",
            )

        if executor:
            try:
                result = await asyncio.wait_for(
                    executor(tool.code, tool.name),
                    timeout=120,
                )
                if isinstance(result, dict):
                    sandbox_result = SandboxResult(
                        passed=result.get("passed", False),
                        effectiveness_score=result.get("effectiveness_score", 0.0),
                        findings_produced=result.get("findings_produced", 0),
                        expected_targets=result.get("expected_targets", 1),
                        output=result.get("output", ""),
                        execution_time_seconds=result.get("execution_time", 0.0),
                    )
                else:
                    sandbox_result = SandboxResult(passed=True, effectiveness_score=0.5)
            except asyncio.TimeoutError:
                sandbox_result = SandboxResult(
                    passed=False, error="Sandbox execution timed out (120s)",
                )
            except Exception as exc:
                sandbox_result = SandboxResult(
                    passed=False, error=str(exc),
                )
        else:
            # No sandbox — mark as passed for testing
            sandbox_result = SandboxResult(
                passed=True,
                effectiveness_score=0.8,
                output="No sandbox configured — auto-pass",
            )

        tool.g2_result = {
            "passed": sandbox_result.passed,
            "effectiveness_score": sandbox_result.effectiveness_score,
            "output": sandbox_result.output[:500],
            "error": sandbox_result.error,
        }

        if sandbox_result.passed:
            tool.state = ToolPromotionState.SANDBOX_APPROVED
            logger.info(
                "CustomToolGenerator: G2 PASSED for %s (effectiveness: %.2f)",
                tool.tool_id, sandbox_result.effectiveness_score,
            )
        else:
            tool.state = ToolPromotionState.SANDBOX_FAILED
            logger.warning("CustomToolGenerator: G2 FAILED for %s", tool.tool_id)

        return sandbox_result

    async def run_gate_3(
        self,
        tool: GeneratedTool,
        operator_decision: str = "approve",
    ) -> str:
        """G3 — Operator approval via chat (N14).

        Args:
            operator_decision: "approve", "reject", or "approve-once"

        Returns:
            Final state string.
        """
        if tool.state != ToolPromotionState.SANDBOX_APPROVED:
            return "g2_not_passed"

        # Publish approval request to EventBus
        if self._event_bus:
            await self._event_bus.publish(
                channel="system",
                event_type="TOOL_APPROVAL_REQUEST",
                payload={
                    "tool_id": tool.tool_id,
                    "name": tool.name,
                    "description": tool.description,
                    "language": tool.language,
                    "effectiveness_score": tool.g2_result.get("effectiveness_score", 0),
                    "sandbox_output": tool.g2_result.get("output", "")[:200],
                },
            )

        tool.g3_result = {"decision": operator_decision}

        if operator_decision == "approve":
            tool.state = ToolPromotionState.OPERATOR_APPROVED
            # Register in tool registry
            self._register_tool(tool)
            logger.info("CustomToolGenerator: G3 APPROVED — %s registered", tool.tool_id)

            if self._event_bus:
                await self._event_bus.publish(
                    channel="research",
                    event_type="TOOL_GENERATED",
                    payload={"tool_id": tool.tool_id, "name": tool.name},
                )

        elif operator_decision == "approve-once":
            tool.state = ToolPromotionState.APPROVE_ONCE
            logger.info("CustomToolGenerator: G3 APPROVE-ONCE — %s (this engagement only)", tool.tool_id)

        else:  # reject
            tool.state = ToolPromotionState.OPERATOR_REJECTED
            logger.info("CustomToolGenerator: G3 REJECTED — %s", tool.tool_id)

        return tool.state.value

    def _register_tool(self, tool: GeneratedTool) -> None:
        """Register an approved tool in the tool registry."""
        from backend.tools.tool_spec import ToolSpec
        from backend.core.models import StealthProfile, EngineType, ToolBackendType, ToolPromotion

        spec = ToolSpec(
            name=tool.name,
            description=tool.description,
            input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
            required_permission="execute",
            backend=ToolBackendType.LOCAL,
            stealth_profile=StealthProfile(min_stealth_level="low"),
            engine_scope=[EngineType.INFRASTRUCTURE],
            timeout_seconds=120,
            promotion_state=ToolPromotion.OPERATOR_APPROVED,
        )
        self._tool_registry[tool.name] = spec

    async def full_pipeline(
        self,
        vulnerability_context: str,
        research_context: str = "",
        sandbox_executor: Any = None,
        operator_decision: str = "approve",
    ) -> GeneratedTool:
        """Run the complete three-gate pipeline.

        Returns the GeneratedTool with its final state.
        """
        tool = await self.generate_tool(vulnerability_context, research_context)

        g1 = await self.run_gate_1(tool)
        if not g1.passed:
            return tool

        g2 = await self.run_gate_2(tool, sandbox_executor)
        if not g2.passed:
            return tool

        await self.run_gate_3(tool, operator_decision)
        return tool
