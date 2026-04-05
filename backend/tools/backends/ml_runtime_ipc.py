"""MLRuntimeIPC — Filesystem-based IPC for ML runtime container (N2).

Implements the v2.0 status-file protocol (Section 6.4):
  task.json        — written by backend to initiate
  task_status.json — written by ml-runtime runner.py at each state transition
  findings.json    — written by ml-runtime on completion

The ml-runtime container has network_mode: none. Communication is
exclusively via a shared Docker volume.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.models import Finding, TaskStatusResult
from backend.tools.backends.ipc_backend import IPCBackend

logger = logging.getLogger(__name__)

# Default shared volume path inside the backend container
DEFAULT_IPC_DIR = Path("/data/ml-runtime-ipc")

# Poll interval for status checks
POLL_INTERVAL_SECONDS = 2.0

# Stale threshold — if task_status.json not updated in this window
# while status is 'running', the task is considered stalled
STALE_THRESHOLD_SECONDS = 120


class MLRuntimeIPC(IPCBackend):
    """Filesystem IPC backend for the ml-runtime container.

    Lifecycle:
      1. submit_task() writes task.json to <ipc_dir>/<task_id>/
      2. ml-runtime runner.py picks up task.json, writes task_status.json
      3. poll_status() reads task_status.json
      4. On completion, get_findings() reads findings.json
      5. cleanup() removes the task directory
    """

    def __init__(self, ipc_dir: Path = DEFAULT_IPC_DIR) -> None:
        self._ipc_dir = ipc_dir

    def _task_dir(self, task_id: str) -> Path:
        return self._ipc_dir / task_id

    def _task_file(self, task_id: str) -> Path:
        return self._task_dir(task_id) / "task.json"

    def _status_file(self, task_id: str) -> Path:
        return self._task_dir(task_id) / "task_status.json"

    def _findings_file(self, task_id: str) -> Path:
        return self._task_dir(task_id) / "findings.json"

    async def submit_task(
        self,
        tool: str,
        tool_input: dict[str, Any],
        timeout_seconds: int,
    ) -> str:
        """Write task.json to shared volume and return task_id."""
        task_id = f"ml-{uuid.uuid4().hex[:12]}"
        task_dir = self._task_dir(task_id)
        task_dir.mkdir(parents=True, exist_ok=True)

        task_payload = {
            "tool": tool,
            "input": tool_input,
            "timeout_seconds": timeout_seconds,
        }

        task_file = self._task_file(task_id)
        await asyncio.to_thread(
            task_file.write_text,
            json.dumps(task_payload, indent=2),
        )

        logger.info(
            "MLRuntimeIPC: submitted task %s (tool=%s, timeout=%ds)",
            task_id, tool, timeout_seconds,
        )
        return task_id

    async def poll_status(self, task_id: str) -> TaskStatusResult:
        """Read task_status.json and return structured status."""
        status_file = self._status_file(task_id)

        if not status_file.exists():
            return TaskStatusResult(status="pending")

        try:
            raw = await asyncio.to_thread(status_file.read_text)
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "MLRuntimeIPC: failed to read status for %s: %s",
                task_id, exc,
            )
            return TaskStatusResult(status="pending")

        started_at = None
        if data.get("started_at"):
            started_at = datetime.fromisoformat(data["started_at"])

        updated_at = None
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"])

        return TaskStatusResult(
            status=data.get("status", "pending"),
            started_at=started_at,
            updated_at=updated_at,
            progress=data.get("progress", 0),
            error=data.get("error"),
        )

    async def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int,
    ) -> TaskStatusResult:
        """Poll until task completes, errors, or times out.

        This is the primary method used by ToolExecutor. It handles:
          - Periodic polling of task_status.json
          - Per-tool timeout enforcement
          - Stale detection (updated_at not refreshed in 120s)

        Returns:
            Final TaskStatusResult (done, error, or timeout).
        """
        deadline = asyncio.get_event_loop().time() + timeout_seconds

        while True:
            status = await self.poll_status(task_id)

            if status.status in ("done", "error"):
                return status

            if status.status == "timeout":
                logger.warning("MLRuntimeIPC: task %s timed out internally", task_id)
                return status

            # Check stale — running but not updating
            if status.status == "running" and status.updated_at:
                now = datetime.now(timezone.utc)
                updated = status.updated_at.replace(tzinfo=timezone.utc)
                elapsed = (now - updated).total_seconds()
                if elapsed > STALE_THRESHOLD_SECONDS:
                    logger.error(
                        "MLRuntimeIPC: task %s stalled (last update %.0fs ago)",
                        task_id, elapsed,
                    )
                    return TaskStatusResult(
                        status="timeout",
                        started_at=status.started_at,
                        updated_at=status.updated_at,
                        progress=status.progress,
                        error=f"Task stalled — no status update in {elapsed:.0f}s",
                    )

            # Check our deadline
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                logger.error(
                    "MLRuntimeIPC: task %s exceeded timeout of %ds",
                    task_id, timeout_seconds,
                )
                return TaskStatusResult(
                    status="timeout",
                    started_at=status.started_at,
                    updated_at=status.updated_at,
                    progress=status.progress,
                    error=f"Per-tool timeout exceeded ({timeout_seconds}s)",
                )

            await asyncio.sleep(min(POLL_INTERVAL_SECONDS, remaining))

    async def get_findings(self, task_id: str) -> list[Finding]:
        """Read findings.json produced by ml-runtime on completion."""
        findings_file = self._findings_file(task_id)

        if not findings_file.exists():
            logger.warning(
                "MLRuntimeIPC: no findings.json for task %s", task_id,
            )
            return []

        try:
            raw = await asyncio.to_thread(findings_file.read_text)
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(
                "MLRuntimeIPC: failed to read findings for %s: %s",
                task_id, exc,
            )
            return []

        findings = []
        for item in data if isinstance(data, list) else [data]:
            findings.append(Finding(
                finding_id=item.get("finding_id", f"{task_id}-{len(findings)}"),
                title=item.get("title", "Untitled finding"),
                severity=item.get("severity", "info"),
                description=item.get("description", ""),
                evidence=item.get("evidence", ""),
                agent=item.get("agent", ""),
                tool=item.get("tool", ""),
                target=item.get("target", ""),
                port=item.get("port"),
                cve_ids=item.get("cve_ids", []),
                attack_techniques=item.get("attack_techniques", []),
                remediation=item.get("remediation", ""),
                metadata=item.get("metadata", {}),
            ))

        return findings

    async def cancel_task(self, task_id: str) -> bool:
        """Write a cancellation marker for the task."""
        cancel_file = self._task_dir(task_id) / "cancel"
        try:
            await asyncio.to_thread(cancel_file.write_text, "cancel")
            return True
        except OSError:
            return False

    async def cleanup(self, task_id: str) -> None:
        """Remove all task artifacts from the shared volume."""
        import shutil
        task_dir = self._task_dir(task_id)
        if task_dir.exists():
            await asyncio.to_thread(shutil.rmtree, str(task_dir), ignore_errors=True)
            logger.info("MLRuntimeIPC: cleaned up task %s", task_id)
