"""Engine 2 — Optimus ICS (Near-term, M4). Section 4.4.

Dedicated compose service with ICSRuntimeIPC backend. Read/audit only.
HumanConfirmGate mandatory before ANY ICS tool call.
"""

from __future__ import annotations

from backend.core.models import EngineResult, EngineStatus, EngineTask, EngineType
from backend.engines.engine_interface import EngineInterface


class EngineICS(EngineInterface):
    """Engine 2 — ICS security engine (stub until M4)."""

    engine_type = EngineType.ICS
    status = EngineStatus.STUB

    async def dispatch(self, task: EngineTask) -> EngineResult:
        return EngineResult(
            task_id=task.task_id,
            engine_type=self.engine_type,
            status="stub",
            error="Engine 2 (ICS) is stub — implementation in M4",
        )

    async def get_available_agents(self) -> list[str]:
        return ["ICSAgent"]
