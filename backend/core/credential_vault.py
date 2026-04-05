"""CredentialVault — Layer 3 of the permission pipeline.

Injects credentials at execution time. Credentials NEVER appear in:
  - LLM context
  - XAI log entries
  - EventBus payloads
  - Any persistent log

VerificationLoop calls are SKIPPED (v2.0 — no credentials for verification).
"""

from __future__ import annotations

import logging
from typing import Any

from backend.core.models import AgentType

logger = logging.getLogger(__name__)


class CredentialVault:
    """Secure credential injection for tool execution.

    Credentials are stored in-memory (loaded from Docker secrets volume
    at startup). They are injected into tool inputs at execution time
    only and never persisted to any log or context.
    """

    def __init__(self) -> None:
        self._credentials: dict[str, dict[str, str]] = {}

    def load_credentials(self, credentials: dict[str, dict[str, str]]) -> None:
        """Load credentials from Docker secrets or .env.

        Args:
            credentials: Mapping of provider -> {key: value} pairs.
                Example: {"aws": {"access_key": "...", "secret_key": "..."}}
        """
        self._credentials = credentials
        logger.info(
            "CredentialVault: loaded credentials for %d providers",
            len(credentials),
        )

    async def inject(
        self,
        tool_input: dict[str, Any],
        caller: AgentType,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """Inject credentials into tool input at execution time.

        Args:
            tool_input: The tool's input dictionary.
            caller: The agent type making the call.
            provider: Optional credential provider key (e.g., 'aws', 'api').

        Returns:
            Updated tool_input dict (credentials injected, or unchanged for verification).
        """
        # v2.0: No credentials for VerificationLoop
        if caller == AgentType.VERIFICATION_LOOP:
            return tool_input

        if provider and provider in self._credentials:
            # Create a copy to avoid mutating the original
            enriched = dict(tool_input)
            enriched["_credentials"] = self._credentials[provider]
            return enriched

        return tool_input

    def has_credentials(self, provider: str) -> bool:
        """Check if credentials exist for a provider."""
        return provider in self._credentials
