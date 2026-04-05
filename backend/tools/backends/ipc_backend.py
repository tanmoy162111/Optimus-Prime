"""IPCBackend — Abstract interface for inter-process communication (N1).

Defines the contract for filesystem-based IPC (local Docker Compose) and
future Redis-based IPC (cloud swap). Tagged with TODO:CLOUD-SWAP.

Two concrete implementations:
  - FilesystemIPCBackend (local) — implemented in ml_runtime_ipc.py / ics_runtime_ipc.py
  - RedisIPCBackend (cloud)     — TODO:CLOUD-SWAP deferred to cloud migration
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from backend.core.models import Finding, TaskStatusResult


class IPCBackend(ABC):
    """Abstract IPC backend for communicating with isolated runtime containers.

    All IPC backends must implement this interface so the ToolExecutor
    can dispatch to any backend uniformly. The concrete backend is
    selected based on deployment configuration.
    """

    @abstractmethod
    async def submit_task(
        self,
        tool: str,
        tool_input: dict[str, Any],
        timeout_seconds: int,
    ) -> str:
        """Submit a task to the runtime container.

        Args:
            tool: Tool name to execute.
            tool_input: Tool-specific input parameters.
            timeout_seconds: Per-tool timeout from ToolSpec.

        Returns:
            task_id: Unique identifier for tracking this task.
        """
        ...

    @abstractmethod
    async def poll_status(self, task_id: str) -> TaskStatusResult:
        """Poll the current status of a submitted task.

        Returns:
            TaskStatusResult with status, progress, timing, and error info.
        """
        ...

    @abstractmethod
    async def get_findings(self, task_id: str) -> list[Finding]:
        """Retrieve findings produced by a completed task.

        Should only be called when poll_status returns status='done'.
        """
        ...

    @abstractmethod
    async def cancel_task(self, task_id: str) -> bool:
        """Attempt to cancel a running task.

        Returns:
            True if cancellation was successful or task was already done.
        """
        ...

    @abstractmethod
    async def cleanup(self, task_id: str) -> None:
        """Clean up task artifacts (files, queues) after completion."""
        ...


# TODO:CLOUD-SWAP — RedisIPCBackend implementation for cloud migration.
# Replace filesystem shared-volume IPC with Redis Streams.
# No application code changes required — swap behind this interface.
