"""ToolExecutor — Dispatches tool calls through the permission pipeline to backends.

Composes the full 7-layer permission pipeline and routes execution
to the appropriate backend handler based on ToolSpec.backend.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from backend.core.base_agent import ToolResult
from backend.core.credential_vault import CredentialVault
from backend.core.hook_runner import HookRunner
from backend.core.models import AgentType, ScopeConfig, StealthLevel
from backend.core.permission import PermissionEnforcer, PermissionPipeline
from backend.core.xai_logger import XAILogger
from backend.tools.tool_spec import ToolSpec

logger = logging.getLogger(__name__)


class ToolExecutor:
    """Executes tools through the permission pipeline.

    The executor holds references to all backend handlers and the
    permission pipeline. It routes tool calls based on ToolSpec.backend.
    """

    def __init__(
        self,
        tool_registry: dict[str, ToolSpec],
        permission_pipeline: PermissionPipeline,
        xai_logger: XAILogger | None = None,
        event_bus: Any = None,
    ) -> None:
        self._registry = tool_registry
        self._pipeline = permission_pipeline
        self._xai_logger = xai_logger
        self._event_bus = event_bus
        self._backends: dict[str, Any] = {}  # Backend handlers registered at startup

    def register_backend(self, backend_type: str, handler: Any) -> None:
        """Register a backend handler for tool execution."""
        self._backends[backend_type] = handler

    async def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        scope: ScopeConfig,
        stealth_level: StealthLevel,
        allowed_tools: frozenset[str],
        agent_id: str,
        agent_type: AgentType,
    ) -> ToolResult:
        """Execute a tool through the full permission pipeline.

        Flow:
          1. Look up ToolSpec in registry
          2. Run pre-execution pipeline (layers 1-6)
          3. Dispatch to backend handler
          4. Run post-execution pipeline (layer 7)
          5. Return result
        """
        # Look up tool spec
        tool_spec = self._registry.get(tool_name)
        if tool_spec is None:
            return ToolResult(
                success=False,
                error=f"Unknown tool: {tool_name}",
            )

        context = {"agent_id": agent_id, "agent_type": agent_type.value}

        # Pre-execution pipeline (layers 1-6)
        tool_input = await self._pipeline.enforce_pre_execution(
            tool_spec=tool_spec,
            tool_input=tool_input,
            scope=scope,
            stealth_level=stealth_level,
            allowed_tools=allowed_tools,
            agent_id=agent_id,
            agent_type=agent_type,
            context=context,
        )

        # Dispatch to backend with timeout enforcement (#19)
        is_error = False
        result_output = None
        timeout = getattr(tool_spec, 'timeout_seconds', 300)
        try:
            backend = self._backends.get(tool_spec.backend.value)
            if backend is None:
                return ToolResult(
                    success=False,
                    error=f"No backend registered for {tool_spec.backend.value}",
                )

            result_output = await asyncio.wait_for(
                backend.execute(tool_name, tool_input, tool_spec),
                timeout=float(timeout),
            )
        except asyncio.TimeoutError:
            is_error = True
            result_output = f"Tool {tool_name} timed out after {timeout}s"
            logger.error("ToolExecutor: %s timed out after %ds", tool_name, timeout)
            if self._event_bus:
                await self._event_bus.publish(
                    channel="system",
                    event_type="TOOL_TIMEOUT",
                    payload={"tool": tool_name, "timeout_seconds": timeout},
                )
        except Exception as exc:
            is_error = True
            result_output = str(exc)
            logger.error("ToolExecutor: %s failed: %s", tool_name, exc)

        # Post-execution pipeline (layer 7)
        await self._pipeline.enforce_post_execution(
            tool_spec=tool_spec,
            tool_input=tool_input,
            result=result_output,
            is_error=is_error,
            context=context,
        )

        if is_error:
            return ToolResult(success=False, error=str(result_output))

        return ToolResult(success=True, output=result_output)
