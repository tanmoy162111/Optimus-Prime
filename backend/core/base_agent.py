"""BaseAgent ABC — Foundation for all security sub-agents (Section 5.1).

Every security sub-agent inherits from BaseAgent, which carries agentic
execution patterns merged with security-specific patterns:
  - Loop guards (max_iterations)
  - Auto-compaction at token thresholds
  - Hook integration
  - Engine assignment and tool namespacing
  - Scope enforcement and stealth awareness
  - Credential vault access
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.core.credential_vault import CredentialVault
from backend.core.hook_runner import HookRunner
from backend.core.models import (
    AgentResult,
    AgentTask,
    AgentType,
    EngineType,
    ScopeConfig,
    StealthLevel,
)
from backend.core.xai_logger import XAILogger

logger = logging.getLogger(__name__)


@dataclass
class AgentAction:
    """An action planned by the agent during its loop."""
    tool_name: str
    tool_input: dict[str, Any]
    reasoning: str


@dataclass
class ToolResult:
    """Result from executing a tool through the permission pipeline."""
    success: bool
    output: Any = None
    error: str | None = None
    is_finding: bool = False
    is_terminal: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_event(self) -> dict[str, Any]:
        """Convert to EventBus event payload."""
        return {
            "success": self.success,
            "is_finding": self.is_finding,
            "is_terminal": self.is_terminal,
            "findings_count": len(self.findings),
            "error": self.error,
        }

    def to_agent_result(self) -> AgentResult:
        """Convert to final AgentResult."""
        return AgentResult(
            status="completed" if self.success else "failed",
            findings=self.findings,
            is_finding=self.is_finding,
            is_terminal=self.is_terminal,
            output=str(self.output)[:2000] if self.output else "",
            error=self.error,
        )


@dataclass
class BaseAgent(ABC):
    """Abstract base for all security sub-agents.

    Subclasses must implement:
      - execute(task) -> AgentResult
      - _plan_next_action(task) -> AgentAction | None

    The run_loop() method provides the agentic execution pattern:
      plan -> check permissions -> execute -> log -> publish -> repeat
    """

    # --- Identity ---
    agent_id: str
    agent_type: AgentType = AgentType.RECON
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(default_factory=frozenset)

    # --- Agentic execution patterns ---
    max_iterations: int = 50
    auto_compaction_threshold: int = 100_000  # tokens

    # --- Security patterns ---
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    stealth_level: StealthLevel = StealthLevel.MEDIUM
    credential_vault: CredentialVault = field(default_factory=CredentialVault)

    # --- Runtime state ---
    session: Any = None  # Session object — injected at runtime
    event_bus: Any = None  # EventBus — injected at runtime
    hook_runner: HookRunner = field(default_factory=HookRunner)
    tool_executor: Any = None  # ToolExecutor — injected at runtime
    xai_logger: XAILogger = field(default_factory=XAILogger)
    kali_mgr: Any = None  # KaliConnectionManager — injected at runtime (v2.0)
    llm_router: Any = None  # LLMRouter — injected at runtime

    @abstractmethod
    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute the agent's primary task. Subclasses implement domain logic."""
        ...

    @abstractmethod
    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        """Plan the next action in the agent loop.

        Returns None when the agent has completed its task or has no more
        actions to take.
        """
        ...

    async def run_loop(self, task: AgentTask) -> AgentResult:
        """Agentic execution loop with guards and compaction (Section 5.1).

        Flow per iteration:
          1. Check iteration limit
          2. Check token count → auto-compact if needed
          3. Plan next action (LLM-driven)
          4. Execute action through permission pipeline
          5. Log decision to XAI
          6. Publish event to EventBus
          7. Check if terminal → return result
        """
        iterations = 0

        while iterations < self.max_iterations:
            iterations += 1

            # Auto-compaction check
            if self.session and hasattr(self.session, 'token_count'):
                if self.session.token_count > self.auto_compaction_threshold:
                    logger.info(
                        "Agent %s: auto-compacting session at %d tokens",
                        self.agent_id, self.session.token_count,
                    )
                    await self.session.compact()

            # Plan next action
            action = await self._plan_next_action(task)
            if action is None:
                break

            # Execute with full permission pipeline
            result = await self._execute_with_permissions(action)

            # Log tool failures for observability
            if not result.success:
                logger.warning(
                    "Agent %s: tool %s FAILED — %s",
                    self.agent_id, action.tool_name, result.error,
                )

            # Parse findings from tool output (#7)
            if result.success and result.output and hasattr(self, "parse_findings_from_output"):
                parsed = self.parse_findings_from_output(action.tool_name, result.output)
                if parsed:
                    result.findings.extend(parsed)
                    result.is_finding = True
                    logger.info(
                        "Agent %s: parsed %d findings from %s",
                        self.agent_id, len(parsed), action.tool_name,
                    )

            # Log to XAI
            await self.xai_logger.log_decision(
                agent=self.__class__.__name__,
                action=f"{action.tool_name}({_sanitize_input(action.tool_input)})",
                result_summary=str(result.output)[:500] if result.output else "",
                reasoning=action.reasoning,
                session_id=getattr(self.session, 'session_id', ''),
            )

            # Publish to EventBus
            if self.event_bus:
                channel = "findings" if result.is_finding else "lifecycle"
                await self.event_bus.publish(
                    channel=channel,
                    event_type=(
                        "FINDING_CREATED" if result.is_finding
                        else "AGENT_RUNNING"
                    ),
                    payload=result.to_event(),
                )

            # Check terminal
            if result.is_terminal:
                return result.to_agent_result()

        return AgentResult(status="max_iterations_reached")

    async def _execute_with_permissions(self, action: AgentAction) -> ToolResult:
        """Execute a tool call through the full permission pipeline.

        Delegates to ToolExecutor which composes all 7 layers.
        """
        if self.tool_executor is None:
            logger.error("Agent %s: no tool_executor configured", self.agent_id)
            return ToolResult(
                success=False,
                error="No tool executor configured",
            )

        try:
            result = await self.tool_executor.execute(
                tool_name=action.tool_name,
                tool_input=action.tool_input,
                scope=self.scope,
                stealth_level=self.stealth_level,
                allowed_tools=self.allowed_tools,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
            )
            return result
        except Exception as exc:
            logger.error(
                "Agent %s: tool %s raised %s: %s",
                self.agent_id, action.tool_name, type(exc).__name__, exc,
            )
            return ToolResult(
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    def parse_findings_from_output(
        self, tool_name: str, output: Any,
    ) -> list:
        """Parse raw tool output into structured findings.

        Override in subclasses to provide tool-specific parsing.
        Default returns empty list.
        """
        return []


def _sanitize_input(tool_input: dict[str, Any]) -> str:
    """Create a safe string representation of tool input for logging."""
    safe = {}
    for k, v in tool_input.items():
        if k.lower() in ("password", "secret", "token", "api_key", "_credentials"):
            safe[k] = "***REDACTED***"
        else:
            safe[k] = str(v)[:100]
    return str(safe)
