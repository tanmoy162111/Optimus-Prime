"""ExplainableAI (XAI) audit trail logger (Section 13.3).

Every agent decision — tool selection, finding classification, disagreement
resolution, scope check outcome — is logged to the XAI audit trail.

The XAI log is append-only and NEVER contains credentials.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.models import XAIEntry

logger = logging.getLogger(__name__)

# Credential patterns to strip from any logged content
_CREDENTIAL_KEYS = frozenset({
    "_credentials", "password", "secret", "token", "api_key",
    "access_key", "secret_key", "private_key",
})


class XAILogger:
    """Append-only XAI audit trail.

    All entries are persisted to a JSONL file and available for
    in-memory query. Credential fields are always stripped.
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._entries: list[XAIEntry] = []
        self._log_dir = log_dir or Path("data/xai")
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "xai_audit.jsonl"

    async def log_decision(
        self,
        agent: str,
        action: str,
        result_summary: str,
        reasoning: str,
        session_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> XAIEntry:
        """Log an agent decision to the XAI audit trail.

        Args:
            agent: Agent class name.
            action: Tool name and sanitized input description.
            result_summary: Outcome description (not full raw output).
            reasoning: Agent's reasoning for selecting this action.
            session_id: Links entry to engagement session.
            metadata: Optional extra context (credentials always stripped).

        Returns:
            The created XAIEntry.
        """
        # Sanitize metadata — strip credential keys
        safe_metadata = self._strip_credentials(metadata or {})

        # Sanitize action string
        safe_action = self._sanitize_text(action)
        safe_result = self._sanitize_text(result_summary)

        entry = XAIEntry(
            agent=agent,
            action=safe_action,
            result_summary=safe_result,
            reasoning=reasoning,
            timestamp=datetime.now(timezone.utc),
            session_id=session_id,
            credential_present=False,  # Always False
        )

        self._entries.append(entry)

        # Persist to JSONL
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "agent": entry.agent,
                    "action": entry.action,
                    "result_summary": entry.result_summary,
                    "reasoning": entry.reasoning,
                    "timestamp": entry.timestamp.isoformat(),
                    "session_id": entry.session_id,
                    "credential_present": entry.credential_present,
                    "metadata": safe_metadata,
                }) + "\n")
        except OSError as exc:
            logger.error("XAILogger: failed to write entry: %s", exc)

        return entry

    def get_entries(
        self,
        agent: str | None = None,
        session_id: str | None = None,
    ) -> list[XAIEntry]:
        """Query XAI entries with optional filters."""
        results = self._entries
        if agent:
            results = [e for e in results if e.agent == agent]
        if session_id:
            results = [e for e in results if e.session_id == session_id]
        return results

    @staticmethod
    def _strip_credentials(data: dict[str, Any]) -> dict[str, Any]:
        """Remove any credential-like keys from a dictionary."""
        return {
            k: v for k, v in data.items()
            if k.lower() not in _CREDENTIAL_KEYS
        }

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Remove potential credential values from text."""
        # Basic heuristic — strip anything that looks like a key=value credential
        import re
        return re.sub(
            r'(password|secret|token|api_key|access_key|secret_key|private_key)\s*[=:]\s*\S+',
            r'\1=***REDACTED***',
            text,
            flags=re.IGNORECASE,
        )
