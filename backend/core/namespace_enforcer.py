"""NamespaceEnforcer — Layer 5 of the permission pipeline.

Validates that an agent is calling a tool within its declared ALLOWED_TOOLS
namespace. Prevents any agent from executing tools outside its boundary.
"""

from __future__ import annotations

import logging

from backend.core.exceptions import ToolPermissionError

logger = logging.getLogger(__name__)


class NamespaceEnforcer:
    """Enforces ALLOWED_TOOLS namespace per agent."""

    @staticmethod
    def check(
        tool_name: str,
        allowed_tools: frozenset[str],
        agent_id: str,
    ) -> None:
        """Verify tool is in the agent's allowed namespace.

        Args:
            tool_name: Tool being invoked.
            allowed_tools: The agent's declared ALLOWED_TOOLS frozenset.
            agent_id: Agent identifier for error reporting.

        Raises:
            ToolPermissionError: If tool is not in agent's namespace.
        """
        if tool_name not in allowed_tools:
            raise ToolPermissionError(
                f"Agent '{agent_id}' attempted to call tool '{tool_name}' "
                f"which is not in its allowed namespace: {sorted(allowed_tools)}"
            )
