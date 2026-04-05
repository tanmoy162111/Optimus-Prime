"""EngineInterface ABC and EngineRouter (Section 4).

Every engine implements EngineInterface for uniform dispatch.
EngineRouter detects target type and dispatches to the correct engine.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.core.models import (
    AgentType,
    EngineResult,
    EngineStatus,
    EngineTask,
    EngineType,
    ScopeConfig,
)

logger = logging.getLogger(__name__)


class EngineInterface(ABC):
    """Abstract base for all engines (Section 4.1)."""

    engine_type: EngineType
    status: EngineStatus

    @abstractmethod
    async def dispatch(self, task: EngineTask) -> EngineResult:
        """Dispatch a task to the appropriate agent within this engine."""
        ...

    @abstractmethod
    async def get_available_agents(self) -> list[str]:
        """Return list of agent class names available in this engine."""
        ...


class EngineRouter:
    """Routes tasks to the correct engine based on target type (Section 4.2).

    Detection logic:
      - IP / Domain / URL / Cloud -> Engine 1 (Infra)
      - Modbus / DNP3 / SCADA    -> Engine 2 (ICS)
      - Model file / LLM API     -> Engine 3 (AI/ML)
      - Mixed                    -> Engine 1 + 3 parallel
    """

    def __init__(self) -> None:
        self._engines: dict[EngineType, EngineInterface] = {}

    def register_engine(self, engine: EngineInterface) -> None:
        """Register an engine instance."""
        self._engines[engine.engine_type] = engine

    def detect_engine(self, scope: ScopeConfig) -> list[EngineType]:
        """Detect which engine(s) should handle this scope."""
        engines = []

        has_ics = scope.ics_interface is not None or any(
            t.lower() in ("modbus", "dnp3", "scada")
            for t in scope.protocols
        )
        has_ml = any(
            t.endswith((".h5", ".pt", ".onnx", ".pkl")) or "llm" in t.lower()
            for t in scope.targets
        )
        has_infra = any(
            not t.endswith((".h5", ".pt", ".onnx", ".pkl"))
            for t in scope.targets
        )

        if has_ics:
            engines.append(EngineType.ICS)
        if has_ml:
            engines.append(EngineType.MLAI)
        if has_infra or not engines:
            engines.append(EngineType.INFRASTRUCTURE)

        return engines

    async def route(self, task: EngineTask) -> list[EngineResult]:
        """Route a task to appropriate engine(s)."""
        results = []
        engine = self._engines.get(task.engine_type)
        if engine is None:
            logger.error("No engine registered for %s", task.engine_type)
            return [EngineResult(
                task_id=task.task_id,
                engine_type=task.engine_type,
                status="error",
                error=f"No engine registered for {task.engine_type}",
            )]

        result = await engine.dispatch(task)
        results.append(result)
        return results
