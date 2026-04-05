"""Engine 1 — Optimus Infra (ACTIVE). Section 4.3.

Primary engine covering network, application, cloud, IAM, endpoint,
and data security domains. All agents use KaliSSH backend.

Agent dispatch: creates agent instances, injects dependencies, calls execute().
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from backend.core.models import (
    AgentResult,
    AgentType,
    EngineResult,
    EngineStatus,
    EngineTask,
    EngineType,
    ScopeConfig,
)
from backend.engines.engine_interface import EngineInterface

logger = logging.getLogger(__name__)

# Agent type -> module path, class name
AGENT_REGISTRY: dict[str, tuple[str, str]] = {
    "recon": ("backend.agents.recon_agent", "ReconAgent"),
    "scan": ("backend.agents.scan_agent", "ScanAgent"),
    "exploit": ("backend.agents.exploit_agent", "ExploitAgent"),
    "intel": ("backend.agents.intel_agent", "IntelAgent"),
    "cloud": ("backend.agents.cloud_agent", "CloudAgent"),
    "iam": ("backend.agents.iam_agent", "IAMAgent"),
    "datasec": ("backend.agents.datasec_agent", "DataSecAgent"),
    "endpoint": ("backend.agents.endpoint_agent", "EndpointAgent"),
    "scope_discovery": ("backend.agents.scope_discovery_agent", "ScopeDiscoveryAgent"),
}


class EngineInfra(EngineInterface):
    """Engine 1 — Infrastructure security engine.

    Dispatches tasks to the correct agent by dynamically loading
    the agent class and injecting runtime dependencies.
    """

    engine_type = EngineType.INFRASTRUCTURE
    status = EngineStatus.ACTIVE

    def __init__(
        self,
        tool_executor: Any = None,
        event_bus: Any = None,
        xai_logger: Any = None,
        kali_mgr: Any = None,
        llm_router: Any = None,
    ) -> None:
        self._tool_executor = tool_executor
        self._event_bus = event_bus
        self._xai_logger = xai_logger
        self._kali_mgr = kali_mgr
        self._llm_router = llm_router

    async def dispatch(self, task: EngineTask) -> EngineResult:
        """Dispatch a task to the appropriate agent within this engine."""
        agent_class_name = task.agent_class
        agent_entry = AGENT_REGISTRY.get(agent_class_name)

        if agent_entry is None:
            logger.error("EngineInfra: unknown agent class %s", agent_class_name)
            return EngineResult(
                task_id=task.task_id,
                engine_type=self.engine_type,
                status="error",
                error=f"Unknown agent class: {agent_class_name}",
            )

        try:
            # Dynamic import
            module_path, class_name = agent_entry
            import importlib
            module = importlib.import_module(module_path)
            agent_cls = getattr(module, class_name)

            # Create agent with dependency injection
            agent = agent_cls(
                agent_id=f"{agent_class_name}-{task.task_id[:8]}",
                scope=task.scope,
                tool_executor=self._tool_executor,
                event_bus=self._event_bus,
                kali_mgr=self._kali_mgr,
                llm_router=self._llm_router,
            )

            if self._xai_logger:
                agent.xai_logger = self._xai_logger

            # Create AgentTask from EngineTask
            from backend.core.models import AgentTask
            agent_task = AgentTask(
                task_id=task.task_id,
                agent_class=agent_class_name,
                prompt=task.prompt,
            )

            # Execute
            result = await agent.execute(agent_task)

            return EngineResult(
                task_id=task.task_id,
                engine_type=self.engine_type,
                agent_results=[result],
                status="completed" if result.status == "completed" else "failed",
            )

        except Exception as exc:
            logger.error(
                "EngineInfra: dispatch failed for %s: %s", agent_class_name, exc,
            )
            return EngineResult(
                task_id=task.task_id,
                engine_type=self.engine_type,
                status="error",
                error=str(exc),
            )

    async def get_available_agents(self) -> list[str]:
        return list(AGENT_REGISTRY.keys())
