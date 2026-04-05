"""Tests for CustomToolGenerator — three-gate workflow (M3 Task 8).

Covers:
  - G1 AST gate: valid tool passes, injection tool fails
  - G2 sandbox: mock execution returns effectiveness score
  - G3 operator flow: approve/reject/approve-once states
  - Full pipeline integration test
"""

from __future__ import annotations

import asyncio

import pytest

from backend.intelligence.custom_tool_generator import (
    ASTSecurityAnalyzer,
    CustomToolGenerator,
    GeneratedTool,
    SandboxResult,
    ToolPromotionState,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer():
    return ASTSecurityAnalyzer()


@pytest.fixture
def generator():
    return CustomToolGenerator(llm_router=None, sandbox_executor=None, event_bus=None)


# ---------------------------------------------------------------------------
# G1 — AST gate
# ---------------------------------------------------------------------------

class TestG1ASTGate:
    """Gate 1 static analysis: valid code passes, dangerous patterns rejected."""

    SAFE_CODE = (
        "import json\n"
        "import sys\n"
        "\n"
        "def main(target):\n"
        "    findings = []\n"
        "    print(json.dumps(findings))\n"
        "\n"
        'if __name__ == "__main__":\n'
        "    main(sys.argv[1])\n"
    )

    SAFE_TOOL_WITH_FILE = (
        "import json\n"
        "def main():\n"
        "    with open('/tmp/optimus_tools/result.json', 'w') as f:\n"
        "        json.dump([], f)\n"
    )

    DANGEROUS_SUBPROCESS = (
        "import subprocess\n"
        "subprocess.run('ls', shell=True)\n"
    )

    DANGEROUS_EVAL = (
        "data = input()\n"
        "eval(data)\n"
    )

    DANGEROUS_EXEC = (
        "code = 'print(1)'\n"
        "exec(code)\n"
    )

    DANGEROUS_OS_SYSTEM = (
        "import os\n"
        "os.system('whoami')\n"
    )

    DANGEROUS_OS_POPEN = (
        "import os\n"
        "os.popen('cat /etc/passwd')\n"
    )

    DANGEROUS_FILE_WRITE = (
        "with open('/etc/shadow', 'w') as f:\n"
        "    f.write('pwned')\n"
    )

    SYNTAX_ERROR_CODE = "def broken(:\n"

    def test_safe_code_passes(self, analyzer):
        result = analyzer.analyze(self.SAFE_CODE)
        assert result.passed is True
        assert len(result.issues) == 0

    def test_safe_file_write_passes(self, analyzer):
        result = analyzer.analyze(self.SAFE_TOOL_WITH_FILE)
        assert result.passed is True

    def test_subprocess_shell_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_SUBPROCESS)
        assert result.passed is False
        assert any("subprocess" in i and "shell=True" in i for i in result.issues)

    def test_eval_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_EVAL)
        assert result.passed is False
        assert any("eval()" in i for i in result.issues)

    def test_exec_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_EXEC)
        assert result.passed is False
        assert any("exec()" in i for i in result.issues)

    def test_os_system_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_OS_SYSTEM)
        assert result.passed is False
        assert any("os.system()" in i for i in result.issues)

    def test_os_popen_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_OS_POPEN)
        assert result.passed is False
        assert any("os.popen()" in i for i in result.issues)

    def test_unsafe_file_write_rejected(self, analyzer):
        result = analyzer.analyze(self.DANGEROUS_FILE_WRITE)
        assert result.passed is False
        assert any("File write outside safe directory" in i for i in result.issues)

    def test_syntax_error_rejected(self, analyzer):
        result = analyzer.analyze(self.SYNTAX_ERROR_CODE)
        assert result.passed is False
        assert any("Syntax error" in i for i in result.issues)

    def test_multiple_issues_detected(self, analyzer):
        """Code with multiple dangerous patterns reports all of them."""
        code = (
            "import os, subprocess\n"
            "eval('x')\n"
            "os.system('id')\n"
            "subprocess.Popen('ls', shell=True)\n"
        )
        result = analyzer.analyze(code)
        assert result.passed is False
        assert len(result.issues) >= 3


# ---------------------------------------------------------------------------
# G2 — Sandbox execution
# ---------------------------------------------------------------------------

class TestG2Sandbox:
    """Gate 2 sandbox execution with mock executors."""

    @pytest.mark.asyncio
    async def test_sandbox_pass_with_mock_executor(self, generator):
        """Mock sandbox executor returns effective result."""
        tool = await generator.generate_tool("SQL injection in login form")
        # Pass G1 first
        await generator.run_gate_1(tool)
        assert tool.state == ToolPromotionState.G1_PASSED

        async def mock_sandbox(code, name):
            return {
                "passed": True,
                "effectiveness_score": 0.85,
                "findings_produced": 3,
                "expected_targets": 1,
                "output": '{"findings": [1,2,3]}',
                "execution_time": 2.5,
            }

        result = await generator.run_gate_2(tool, sandbox_executor=mock_sandbox)
        assert result.passed is True
        assert result.effectiveness_score == 0.85
        assert result.findings_produced == 3
        assert tool.state == ToolPromotionState.SANDBOX_APPROVED

    @pytest.mark.asyncio
    async def test_sandbox_fail_returns_error(self, generator):
        """Sandbox failure sets SANDBOX_FAILED state."""
        tool = await generator.generate_tool("XSS in search")
        await generator.run_gate_1(tool)

        async def failing_sandbox(code, name):
            return {"passed": False, "effectiveness_score": 0.0, "output": "", "error": "Crash"}

        result = await generator.run_gate_2(tool, sandbox_executor=failing_sandbox)
        assert result.passed is False
        assert tool.state == ToolPromotionState.SANDBOX_FAILED

    @pytest.mark.asyncio
    async def test_sandbox_timeout(self, generator):
        """Sandbox timeout (>120s) fails gracefully."""
        tool = await generator.generate_tool("slow vuln")
        await generator.run_gate_1(tool)

        async def slow_sandbox(code, name):
            await asyncio.sleep(300)
            return {"passed": True}

        result = await generator.run_gate_2(tool, sandbox_executor=slow_sandbox)
        assert result.passed is False
        assert "timed out" in result.error.lower()
        assert tool.state == ToolPromotionState.SANDBOX_FAILED

    @pytest.mark.asyncio
    async def test_sandbox_skipped_if_g1_failed(self, generator):
        """Cannot run G2 if G1 not passed."""
        tool = GeneratedTool(
            tool_id="test-001",
            name="bad_tool",
            description="test",
            code="eval('x')",
            state=ToolPromotionState.G1_FAILED,
        )
        result = await generator.run_gate_2(tool)
        assert result.passed is False
        assert "G1 not passed" in result.error

    @pytest.mark.asyncio
    async def test_no_sandbox_auto_pass(self, generator):
        """No sandbox configured — auto-pass with 0.8 effectiveness."""
        tool = await generator.generate_tool("test vuln")
        await generator.run_gate_1(tool)
        result = await generator.run_gate_2(tool)
        assert result.passed is True
        assert result.effectiveness_score == 0.8
        assert tool.state == ToolPromotionState.SANDBOX_APPROVED


# ---------------------------------------------------------------------------
# G3 — Operator approval
# ---------------------------------------------------------------------------

class TestG3OperatorApproval:
    """Gate 3 operator decision: approve, reject, approve-once."""

    async def _get_sandbox_approved_tool(self, generator) -> GeneratedTool:
        tool = await generator.generate_tool("SSRF in API")
        await generator.run_gate_1(tool)
        await generator.run_gate_2(tool)  # auto-pass (no sandbox)
        assert tool.state == ToolPromotionState.SANDBOX_APPROVED
        return tool

    @pytest.mark.asyncio
    async def test_approve_registers_tool(self, generator):
        tool = await self._get_sandbox_approved_tool(generator)
        state = await generator.run_gate_3(tool, "approve")
        assert state == "operator_approved"
        assert tool.state == ToolPromotionState.OPERATOR_APPROVED
        assert tool.name in generator._tool_registry

    @pytest.mark.asyncio
    async def test_reject(self, generator):
        tool = await self._get_sandbox_approved_tool(generator)
        state = await generator.run_gate_3(tool, "reject")
        assert state == "operator_rejected"
        assert tool.state == ToolPromotionState.OPERATOR_REJECTED
        assert tool.name not in generator._tool_registry

    @pytest.mark.asyncio
    async def test_approve_once(self, generator):
        tool = await self._get_sandbox_approved_tool(generator)
        state = await generator.run_gate_3(tool, "approve-once")
        assert state == "approve_once"
        assert tool.state == ToolPromotionState.APPROVE_ONCE

    @pytest.mark.asyncio
    async def test_g3_blocked_without_g2(self, generator):
        """Cannot run G3 if G2 not passed."""
        tool = await generator.generate_tool("test")
        await generator.run_gate_1(tool)
        # Skip G2
        state = await generator.run_gate_3(tool, "approve")
        assert state == "g2_not_passed"


# ---------------------------------------------------------------------------
# Full pipeline integration
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """End-to-end three-gate pipeline tests."""

    @pytest.mark.asyncio
    async def test_full_pipeline_approve(self, generator):
        """Full pipeline with approval -> OPERATOR_APPROVED."""
        tool = await generator.full_pipeline(
            vulnerability_context="SQL injection in /api/users endpoint",
            operator_decision="approve",
        )
        assert tool.state == ToolPromotionState.OPERATOR_APPROVED
        assert tool.g1_result["passed"] is True
        assert tool.g2_result["passed"] is True
        assert tool.g3_result["decision"] == "approve"
        assert tool.name in generator._tool_registry

    @pytest.mark.asyncio
    async def test_full_pipeline_reject(self, generator):
        """Full pipeline with rejection -> OPERATOR_REJECTED."""
        tool = await generator.full_pipeline(
            vulnerability_context="XSS in search",
            operator_decision="reject",
        )
        assert tool.state == ToolPromotionState.OPERATOR_REJECTED

    @pytest.mark.asyncio
    async def test_full_pipeline_with_sandbox(self, generator):
        """Full pipeline with custom sandbox executor."""
        async def sandbox(code, name):
            return {"passed": True, "effectiveness_score": 0.9, "findings_produced": 5,
                    "expected_targets": 1, "output": "ok", "execution_time": 1.0}

        tool = await generator.full_pipeline(
            vulnerability_context="RCE via deserialization",
            sandbox_executor=sandbox,
            operator_decision="approve",
        )
        assert tool.state == ToolPromotionState.OPERATOR_APPROVED
        assert tool.g2_result["effectiveness_score"] == 0.9

    @pytest.mark.asyncio
    async def test_pipeline_stops_on_g1_fail(self):
        """If G1 fails, pipeline stops — no G2/G3."""
        gen = CustomToolGenerator()
        # Create tool with dangerous code directly
        tool = await gen.generate_tool("test")
        tool.code = "import os\nos.system('rm -rf /')\n"
        g1 = await gen.run_gate_1(tool)
        assert g1.passed is False
        assert tool.state == ToolPromotionState.G1_FAILED
        # G2 should refuse
        g2 = await gen.run_gate_2(tool)
        assert g2.passed is False

    @pytest.mark.asyncio
    async def test_pipeline_stops_on_g2_fail(self, generator):
        """If G2 fails, pipeline stops — no G3."""
        async def bad_sandbox(code, name):
            return {"passed": False, "error": "exploit failed"}

        tool = await generator.full_pipeline(
            vulnerability_context="LFI in download endpoint",
            sandbox_executor=bad_sandbox,
        )
        assert tool.state == ToolPromotionState.SANDBOX_FAILED
        assert tool.g3_result == {}  # G3 never ran

    @pytest.mark.asyncio
    async def test_multiple_tools_independent(self, generator):
        """Multiple tools go through pipeline independently."""
        tool1 = await generator.full_pipeline("SQLi", operator_decision="approve")
        tool2 = await generator.full_pipeline("XSS", operator_decision="reject")

        assert tool1.state == ToolPromotionState.OPERATOR_APPROVED
        assert tool2.state == ToolPromotionState.OPERATOR_REJECTED
        assert tool1.name in generator._tool_registry
        assert tool2.name not in generator._tool_registry
