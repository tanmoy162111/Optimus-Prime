"""ICSRuntimeIPC backend stub — filesystem IPC for ICS runtime (Section 4.4).

Mirrors MLRuntimeIPC protocol. Implementation in M4.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.core.models import Finding, TaskStatusResult
from backend.tools.backends.ipc_backend import IPCBackend


class ICSRuntimeIPC(IPCBackend):
    """Filesystem IPC for the ics-runtime container. Stub until M4."""

    def __init__(self, ipc_dir: Path = Path("/data/ics-runtime-ipc")) -> None:
        self._ipc_dir = ipc_dir

    async def submit_task(self, tool: str, tool_input: dict[str, Any], timeout_seconds: int) -> str:
        raise NotImplementedError("ICSRuntimeIPC: stub — implementation in M4")

    async def poll_status(self, task_id: str) -> TaskStatusResult:
        return TaskStatusResult(status="pending")

    async def get_findings(self, task_id: str) -> list[Finding]:
        return []

    async def cancel_task(self, task_id: str) -> bool:
        return False

    async def cleanup(self, task_id: str) -> None:
        pass
