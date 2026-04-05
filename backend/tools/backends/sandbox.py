"""SandboxOnDemand backend — ephemeral container for tool validation (Section 6.2).

Provides sandbox execution capabilities for custom tool validation
against DVWA. Executes tool code in isolated subprocess with timeout.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SANDBOX_TIMEOUT = 120  # Maximum execution time in seconds


class SandboxOnDemandBackend:
    """Sandbox backend for custom tool validation against DVWA.

    Executes generated tool code in an isolated subprocess with:
      - Timeout enforcement (max 120s)
      - Output capture for effectiveness scoring
      - Temporary file cleanup after execution
    """

    def __init__(self, dvwa_url: str = "http://sandbox:80") -> None:
        self._dvwa_url = dvwa_url

    async def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_spec: Any = None,
    ) -> dict[str, Any]:
        """Execute a tool against the sandbox (standard ToolBackend interface)."""
        code = tool_input.get("code", "")
        target = tool_input.get("target", self._dvwa_url)

        if not code:
            return {"status": "error", "error": "No code provided"}

        return await self.run_tool_code(code, tool_name, target)

    async def run_tool_code(
        self,
        code: str,
        tool_name: str,
        target: str = "http://sandbox:80",
        timeout: int = SANDBOX_TIMEOUT,
    ) -> dict[str, Any]:
        """Execute tool code in a subprocess with timeout.

        Args:
            code: Python source code to execute.
            tool_name: Name for the tool (used in temp file).
            target: Target URL/host for the tool.
            timeout: Maximum execution seconds.

        Returns:
            Dict with status, output, effectiveness metrics.
        """
        # Write code to temp file
        tmp_dir = Path(tempfile.mkdtemp(prefix="optimus_sandbox_"))
        script_path = tmp_dir / f"{tool_name}.py"
        script_path.write_text(code)

        try:
            proc = await asyncio.create_subprocess_exec(
                "python3", str(script_path), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(tmp_dir),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
                stdout_str = stdout.decode("utf-8", errors="replace")
                stderr_str = stderr.decode("utf-8", errors="replace")

                return {
                    "status": "success" if proc.returncode == 0 else "error",
                    "tool": tool_name,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "exit_code": proc.returncode,
                    "passed": proc.returncode == 0,
                    "effectiveness_score": self._compute_effectiveness(stdout_str),
                    "findings_produced": self._count_findings(stdout_str),
                    "output": stdout_str[:1000],
                }

            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "status": "timeout",
                    "tool": tool_name,
                    "error": f"Execution timed out after {timeout}s",
                    "passed": False,
                    "effectiveness_score": 0.0,
                }

        except Exception as exc:
            return {
                "status": "error",
                "tool": tool_name,
                "error": str(exc),
                "passed": False,
                "effectiveness_score": 0.0,
            }

        finally:
            # Cleanup
            try:
                script_path.unlink(missing_ok=True)
                tmp_dir.rmdir()
            except OSError:
                pass

    @staticmethod
    def _compute_effectiveness(output: str) -> float:
        """Compute effectiveness score from tool output."""
        if not output:
            return 0.0

        # Simple heuristic: more findings = higher score
        import json
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return min(1.0, len(data) / 5.0)
            if isinstance(data, dict) and "findings" in data:
                return min(1.0, len(data["findings"]) / 5.0)
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: check for indicators of success
        indicators = ["vulnerability", "found", "detected", "confirmed", "exploit"]
        matches = sum(1 for ind in indicators if ind in output.lower())
        return min(1.0, matches / 3.0)

    @staticmethod
    def _count_findings(output: str) -> int:
        """Count findings in tool output."""
        import json
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict) and "findings" in data:
                return len(data["findings"])
        except (json.JSONDecodeError, TypeError):
            pass
        return 0
