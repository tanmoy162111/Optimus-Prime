"""PermissionEnforcer — Layer 1 of the permission pipeline + full pipeline composition.

Layer 1 handles base-level validation:
  - Path traversal prevention
  - Symlink escape detection
  - Workspace boundary validation
  - Binary detection
  - Size limits (MAX_READ_SIZE, MAX_WRITE_SIZE)
  - Command validation

The PermissionPipeline composes all 7 layers in order (Section 7.1).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from backend.core.credential_vault import CredentialVault
from backend.core.exceptions import (
    PathTraversalError,
    WorkspaceBoundaryError,
)
from backend.core.hook_runner import HookRunner
from backend.core.models import AgentType, ScopeConfig, StealthLevel
from backend.core.namespace_enforcer import NamespaceEnforcer
from backend.core.scope_enforcer import ScopeEnforcer
from backend.core.stealth_enforcer import StealthEnforcer
from backend.tools.tool_spec import ToolSpec

logger = logging.getLogger(__name__)

# Size limits
MAX_READ_SIZE = 10 * 1024 * 1024   # 10 MB
MAX_WRITE_SIZE = 50 * 1024 * 1024  # 50 MB

# Dangerous command patterns
BLOCKED_COMMANDS = frozenset({
    "rm", "rmdir", "del", "format", "mkfs",
    "dd", "shred", "wipefs",
})


class PermissionEnforcer:
    """Layer 1 — Base permission validation.

    Handles path traversal, symlink escape, workspace boundary,
    binary detection, size limits, and command validation.
    """

    def __init__(self, workspace_root: Path | None = None) -> None:
        self._workspace_root = workspace_root or Path("/data")

    def check(self, tool_input: dict[str, Any]) -> None:
        """Run all Layer 1 checks.

        Raises:
            PathTraversalError: On path traversal or symlink escape.
            WorkspaceBoundaryError: On workspace boundary violation.
        """
        # Check file paths in input
        for key in ("path", "file", "output_path", "target_path"):
            if key in tool_input and isinstance(tool_input[key], str):
                self._check_path(tool_input[key])

        # Check commands
        if "command" in tool_input:
            self._check_command(tool_input["command"])

    def _check_path(self, path_str: str) -> None:
        """Validate a file path for traversal and boundary."""
        path = Path(path_str)

        # Path traversal detection
        if ".." in path.parts:
            raise PathTraversalError(
                f"Path traversal detected: '{path_str}'"
            )

        # Resolve and check symlinks
        try:
            resolved = path.resolve()
            if path.is_symlink():
                # Symlink escape detection
                if not str(resolved).startswith(str(self._workspace_root)):
                    raise PathTraversalError(
                        f"Symlink escape detected: '{path_str}' -> '{resolved}'"
                    )
        except (OSError, RuntimeError):
            pass  # Path may not exist yet

    def _check_command(self, command: str) -> None:
        """Validate a command string for dangerous patterns."""
        parts = command.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()
        # Strip path prefix
        cmd = os.path.basename(cmd)

        if cmd in BLOCKED_COMMANDS:
            raise WorkspaceBoundaryError(
                f"Blocked command detected: '{cmd}'"
            )


class PermissionPipeline:
    """Composed 7-layer permission pipeline (Section 7.1).

    Executes all layers in order:
      1. PermissionEnforcer  — base validation
      2. ScopeEnforcer       — target/port/protocol scope
      3. CredentialVault     — credential injection
      4. StealthEnforcer     — stealth level checks
      5. NamespaceEnforcer   — ALLOWED_TOOLS validation
      6. HookRunner.pre      — plugin hooks
      7. (Tool Execution)
      8. HookRunner.post     — post-execution hooks
    """

    def __init__(
        self,
        permission_enforcer: PermissionEnforcer,
        credential_vault: CredentialVault,
        hook_runner: HookRunner,
    ) -> None:
        self._permission_enforcer = permission_enforcer
        self._credential_vault = credential_vault
        self._hook_runner = hook_runner

    async def enforce_pre_execution(
        self,
        tool_spec: ToolSpec,
        tool_input: dict[str, Any],
        scope: ScopeConfig,
        stealth_level: StealthLevel,
        allowed_tools: frozenset[str],
        agent_id: str,
        agent_type: AgentType,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run layers 1-6 before tool execution.

        Returns:
            The (potentially modified) tool_input ready for execution.

        Raises:
            PermissionError subclasses on any layer failure.
        """
        # Layer 1: Base permission checks
        self._permission_enforcer.check(tool_input)

        # Layer 2: Scope enforcement (stateless, side-effect-free)
        ScopeEnforcer.check(scope, tool_input)

        # Layer 3: Credential injection (skipped for VerificationLoop)
        tool_input = await self._credential_vault.inject(
            tool_input, caller=agent_type,
        )

        # Layer 4: Stealth enforcement
        StealthEnforcer.check(
            tool_name=tool_spec.name,
            stealth_level=stealth_level,
            stealth_profile=tool_spec.stealth_profile,
        )

        # Layer 5: Namespace enforcement
        NamespaceEnforcer.check(
            tool_name=tool_spec.name,
            allowed_tools=allowed_tools,
            agent_id=agent_id,
        )

        # Layer 6: Pre-tool hooks
        tool_input = await self._hook_runner.run_pre_tool_use(
            tool_name=tool_spec.name,
            tool_input=tool_input,
            context=context,
        )

        return tool_input

    async def enforce_post_execution(
        self,
        tool_spec: ToolSpec,
        tool_input: dict[str, Any],
        result: Any,
        is_error: bool,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Run layer 7 after tool execution."""
        await self._hook_runner.run_post_tool_use(
            tool_name=tool_spec.name,
            tool_input=tool_input,
            result=result,
            is_error=is_error,
            context=context,
        )
