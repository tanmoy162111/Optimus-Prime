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
    StealthLevel,
)
from backend.engines.engine_interface import EngineInterface

logger = logging.getLogger(__name__)


class _VerificationLoopAdapter:
    """Thin BaseAgent-compatible wrapper around VerificationLoop.

    EngineInfra requires agent classes with an async execute(task) -> AgentResult
    interface.  VerificationLoop does not inherit from BaseAgent, so this
    adapter bridges the gap without modifying VerificationLoop itself.
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        engine: EngineType,
        scope: ScopeConfig,
        tool_executor: Any = None,
        event_bus: Any = None,
        kali_mgr: Any = None,
        llm_router: Any = None,
    ) -> None:
        from backend.verification.verification_loop import VerificationLoop
        self._loop = VerificationLoop(
            tool_executor=tool_executor,
            event_bus=event_bus,
            scope=scope,
        )
        self._scope = scope
        self.xai_logger = None  # may be injected by EngineInfra

    async def execute(self, task: Any) -> AgentResult:
        """Execute verification against findings from the task prompt or EventBus.

        The task prompt may be a JSON-encoded list of finding dicts, or plain
        text (e.g. "Execute Verification phase against 10.0.0.1").  When the
        prompt is not parseable as a finding list, fall back to reading all
        FINDING_CREATED events from the EventBus so the verification phase
        always has access to findings produced by earlier phases.
        """
        import json

        # Forward injected xai_logger to inner VerificationLoop before executing
        if self.xai_logger:
            self._loop._xai_logger = self.xai_logger

        findings: list[dict] = []
        try:
            parsed = json.loads(task.prompt)
            if isinstance(parsed, list):
                findings = parsed
        except (json.JSONDecodeError, AttributeError):
            findings = []

        # Fallback: load findings from EventBus when prompt is plain text
        if not findings and self._loop._event_bus:
            try:
                events = await self._loop._event_bus.replay(0)
                findings = [
                    e["payload"]
                    for e in events
                    if e.get("event_type") == "FINDING_CREATED"
                    and isinstance(e.get("payload"), dict)
                ]
            except Exception:
                findings = []

        if not findings:
            return AgentResult(
                status="completed",
                output="VerificationLoop: no findings to verify",
            )

        classifications = await self._loop.verify_findings_batch(findings)
        confirmed = [fid for fid, cls in classifications.items() if cls.value == "confirmed"]
        return AgentResult(
            status="completed",
            output=f"VerificationLoop: verified {len(findings)} finding(s); {len(confirmed)} confirmed",
            findings=findings,
            metadata={"classifications": {k: v.value for k, v in classifications.items()}},
        )

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
    # VerificationLoop is registered via its BaseAgent-compatible adapter
    # so that EngineInfra can dispatch verify phases without special-casing.
    "verification_loop": (None, None),  # sentinel — handled directly below
}

# Sentinel value used for the verification_loop entry
_VERIFICATION_LOOP_ADAPTER = _VerificationLoopAdapter


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
        strategy_engine: Any = None,
    ) -> None:
        self._tool_executor = tool_executor
        self._event_bus = event_bus
        self._xai_logger = xai_logger
        self._kali_mgr = kali_mgr
        self._llm_router = llm_router
        self._strategy_engine = strategy_engine

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
            import importlib

            # Resolve AgentType from the agent class name string
            try:
                _agent_type = AgentType(agent_class_name)
            except ValueError:
                _agent_type = AgentType.RECON  # safe fallback

            # Resolve agent class — VerificationLoop uses the local adapter
            module_path, class_name = agent_entry
            if module_path is None:
                agent_cls = _VERIFICATION_LOOP_ADAPTER
            else:
                module = importlib.import_module(module_path)
                agent_cls = getattr(module, class_name)

            # Create agent with dependency injection
            agent = agent_cls(
                agent_id=f"{agent_class_name}-{task.task_id[:8]}",
                agent_type=_agent_type,
                engine=task.engine_type,
                scope=task.scope,
                tool_executor=self._tool_executor,
                event_bus=self._event_bus,
                kali_mgr=self._kali_mgr,
                llm_router=self._llm_router,
            )

            if self._xai_logger:
                agent.xai_logger = self._xai_logger

            # Inject strategy_engine into IntelAgent
            if agent_class_name == "intel" and self._strategy_engine:
                agent.strategy_engine = self._strategy_engine

            # Create AgentTask from EngineTask
            from backend.core.models import AgentTask
            agent_task = AgentTask(
                task_id=task.task_id,
                agent_class=agent_class_name,
                prompt=task.prompt,
            )

            # Execute
            result = await agent.execute(agent_task)

            _PARTIAL_SUCCESS = {"completed", "max_iterations_reached"}
            return EngineResult(
                task_id=task.task_id,
                engine_type=self.engine_type,
                agent_results=[result],
                status="completed" if result.status in _PARTIAL_SUCCESS else "failed",
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
