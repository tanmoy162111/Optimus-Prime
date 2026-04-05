"""HookRunner — Layers 6 and 7 of the permission pipeline.

Manages pre-tool and post-tool hooks including:
  - Plugin validation hooks
  - Custom tool sandbox gate
  - HumanConfirmGate check (ICS tools — v2.0)
  - Verification hook
  - XAI logging hook
  - Effectiveness tracking hook
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.core.exceptions import HookDeniedError

logger = logging.getLogger(__name__)


@dataclass
class HookResult:
    """Result from a hook execution."""
    denied: bool = False
    reason: str = ""
    updated_input: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class PreToolHook(ABC):
    """Abstract base for pre-tool execution hooks."""

    @abstractmethod
    async def run(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> HookResult:
        """Execute the hook before tool execution.

        Can deny execution, modify input, or add context.
        """
        ...


class PostToolHook(ABC):
    """Abstract base for post-tool execution hooks."""

    @abstractmethod
    async def run(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        result: Any,
        is_error: bool,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Execute the hook after tool execution.

        Post hooks cannot deny — execution already occurred.
        """
        ...


class HumanConfirmGate(ABC):
    """Abstract base for mandatory operator confirmation gates (v2.0 N12).

    Any engine or agent can inherit to insert mandatory operator checkpoints.
    Engine 2 uses it for all ICS tool execution.
    """

    @abstractmethod
    def gate_keyword(self) -> str:
        """The keyword operator must type to confirm (e.g., 'confirm-ics')."""
        ...

    @abstractmethod
    def gate_description(self) -> str:
        """Human-readable description of what this gate protects."""
        ...

    async def await_confirmation(self, session: Any) -> bool:
        """Publish CONFIRMATION_REQUIRED event and block until confirmed.

        Times out after 300 seconds — returns False (task aborted).
        """
        # Stub — will be wired to EventBus and WebSocket in M1
        logger.warning(
            "HumanConfirmGate: awaiting '%s' confirmation (stub)",
            self.gate_keyword(),
        )
        return False


class HookRunner:
    """Manages and executes pre-tool and post-tool hook pipelines.

    Hook pipeline overhead target: <= 10ms per tool call (Suite 5 benchmark).
    """

    def __init__(self) -> None:
        self._pre_hooks: list[PreToolHook] = []
        self._post_hooks: list[PostToolHook] = []

    def register_pre_hook(self, hook: PreToolHook) -> None:
        """Register a pre-tool execution hook."""
        self._pre_hooks.append(hook)

    def register_post_hook(self, hook: PostToolHook) -> None:
        """Register a post-tool execution hook."""
        self._post_hooks.append(hook)

    async def run_pre_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute all pre-tool hooks in order.

        Args:
            tool_name: Name of the tool about to execute.
            tool_input: Tool input dictionary (may be modified by hooks).
            context: Optional context (agent info, session, etc.).

        Returns:
            Potentially modified tool_input.

        Raises:
            HookDeniedError: If any hook denies execution.
        """
        current_input = tool_input

        for hook in self._pre_hooks:
            result = await hook.run(tool_name, current_input, context)
            if result.denied:
                raise HookDeniedError(result.reason)
            if result.updated_input is not None:
                current_input = result.updated_input

        return current_input

    async def run_post_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        result: Any,
        is_error: bool,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Execute all post-tool hooks in order.

        Post hooks cannot deny — execution already occurred.
        """
        for hook in self._post_hooks:
            try:
                await hook.run(tool_name, tool_input, result, is_error, context)
            except Exception as exc:
                logger.error(
                    "PostToolHook %s failed for tool %s: %s",
                    hook.__class__.__name__, tool_name, exc,
                )
