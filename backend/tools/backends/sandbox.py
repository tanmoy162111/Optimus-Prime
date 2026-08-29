"""SandboxOnDemand backend — ephemeral container for tool validation (Section 6.2).

Provides sandbox execution capabilities for custom tool validation
against DVWA. Executes tool code inside an isolated Docker container
(--network=none --memory=256m, auto-removed after use) via docker-py,
wrapped in asyncio.to_thread since the SDK is synchronous (SEC-01).

NOTE (RESEARCH.md Pitfall #3, forward-looking for v1.1 Phase 9): running
with network_mode="none" blocks reachability to `dvwa_url`
("http://sandbox:80" by default) from inside the sandbox container.
Validating generated tools against a live DVWA target therefore does not
work yet once this backend is wired up to a live caller — resolving that
tension (e.g. a dedicated sandbox+DVWA-only network) is out of scope for
this phase (D-02: this backend has zero live callers this phase).
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import tarfile
from typing import Any

import docker
from docker.errors import APIError, ContainerError, ImageNotFound

logger = logging.getLogger(__name__)

SANDBOX_TIMEOUT = 120  # Maximum execution time in seconds

# Tool names become both a Docker tar-archive entry name and (historically) a
# host filesystem path segment. Restricting to a conservative allowlist closes
# both path-traversal (host) and tar-slip (container) vectors — CR-02.
_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Minimal stdlib-only base image (RESEARCH.md Open Question #2). v1.1 Phase 9
# may swap this for a custom image pre-loaded with common libraries once real
# generated-tool code samples exist to inform what needs to be baked in.
SANDBOX_IMAGE = "python:3.12-slim"


class SandboxOnDemandBackend:
    """Sandbox backend for custom tool validation against DVWA.

    Executes generated tool code inside an isolated Docker container with:
      - --network=none (no network access) and --memory=256m memory cap
      - Timeout enforcement (max 120s), container killed+removed on timeout
      - Output capture for effectiveness scoring
      - Ephemeral container removal after every run (no leaked containers)
      - tool_name validated against an allowlist before use in any path/archive entry
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
        """Execute tool code inside an isolated Docker container with timeout.

        Args:
            code: Python source code to execute.
            tool_name: Name for the tool (used as the in-container script filename).
            target: Target URL/host for the tool.
            timeout: Maximum execution seconds.

        Returns:
            Dict with status, output, effectiveness metrics.
        """
        if not _SAFE_TOOL_NAME.match(tool_name):
            return {
                "status": "error",
                "tool": tool_name,
                "error": f"Invalid tool_name: {tool_name!r}",
                "passed": False,
                "effectiveness_score": 0.0,
            }

        try:
            try:
                exit_code, stdout_str, stderr_str = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._run_sync, code, tool_name, target, timeout,
                    ),
                    timeout=timeout + 5,  # outer guard slightly longer than inner container.wait timeout
                )

                return {
                    "status": "success" if exit_code == 0 else "error",
                    "tool": tool_name,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "exit_code": exit_code,
                    "passed": exit_code == 0,
                    "effectiveness_score": self._compute_effectiveness(stdout_str),
                    "findings_produced": self._count_findings(stdout_str),
                    "output": stdout_str[:1000],
                }

            except TimeoutError:
                # asyncio.TimeoutError IS builtins.TimeoutError on Python 3.11+,
                # so this catches both: (a) _run_sync's own container.wait()
                # read-timeout (re-raised as TimeoutError, container already
                # killed+removed inside _run_sync's finally), and (b) the
                # outer asyncio.wait_for guard firing if the thread itself
                # hangs beyond timeout+5.
                return {
                    "status": "timeout",
                    "tool": tool_name,
                    "error": f"Execution timed out after {timeout}s",
                    "passed": False,
                    "effectiveness_score": 0.0,
                }

        except (ImageNotFound, APIError, ContainerError) as exc:
            return {
                "status": "error",
                "tool": tool_name,
                "error": str(exc),
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

    @staticmethod
    def _build_script_tar(tool_name: str, code: str) -> bytes:
        """Tar up the script as `/work/<tool_name>.py`, in-memory (no disk I/O).

        Injected into the container via `put_archive()` rather than a bind
        mount: the backend itself runs inside a container (DooD, D-10), and
        `client.containers.run(..., volumes={host_path: ...})` resolves
        `host_path` against the Docker *daemon's* host filesystem, not the
        caller's own container filesystem — a plain tempfile path created
        inside the backend container is invisible to the daemon and silently
        mounts an empty directory. `put_archive()` streams file bytes
        directly over the Docker Engine API and has no such path-mapping
        problem.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            data = code.encode("utf-8")
            info = tarfile.TarInfo(name=f"work/{tool_name}.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    @staticmethod
    def _run_sync(
        code: str, tool_name: str, target: str, timeout: int,
    ) -> tuple[int, str, str]:
        """Blocking docker-py container run — call via asyncio.to_thread.

        Uses remove=False + explicit container.remove(force=True) in a
        finally block rather than auto_remove=True, since auto_remove races
        client-side log reads for fast-exiting scripts (docker/docker-py
        issues #1813, #3289 — RESEARCH.md Pitfall #2).

        container.wait(timeout=N) is a client-side read timeout on the
        wait-for-exit HTTP call, not a guarantee the container itself is
        killed (RESEARCH.md Assumption A3) — on that read-timeout we
        explicitly kill the container here (we hold the direct reference,
        no ancestor-filter guessing needed) and re-raise as TimeoutError so
        the caller can report status="timeout".
        """
        client = docker.from_env()
        container = client.containers.create(
            SANDBOX_IMAGE,
            command=["python3", f"/work/{tool_name}.py", target],
            network_mode="none",
            mem_limit="256m",
        )
        try:
            tar_bytes = SandboxOnDemandBackend._build_script_tar(tool_name, code)
            container.put_archive("/", tar_bytes)
            container.start()

            try:
                result = container.wait(timeout=timeout)
            except Exception as wait_exc:
                try:
                    container.kill()
                except APIError:
                    pass
                raise TimeoutError(
                    f"container wait timed out after {timeout}s",
                ) from wait_exc

            exit_code = result.get("StatusCode", -1)
            stdout_str = container.logs(stdout=True, stderr=False).decode(
                "utf-8", errors="replace",
            )
            stderr_str = container.logs(stdout=False, stderr=True).decode(
                "utf-8", errors="replace",
            )
            return exit_code, stdout_str, stderr_str
        finally:
            try:
                container.remove(force=True)
            except APIError:
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
