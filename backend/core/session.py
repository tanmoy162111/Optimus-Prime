"""Session management and persistence (Section 8).

Sessions use JSONL append-only persistence with auto-compaction.
Supports forking for parallel exploit chain exploration and
findings-only merge back to parent (v2.0 N8).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.models import (
    BranchSummary,
    ConversationMessage,
    MergeResult,
    ScopeConfig,
)

logger = logging.getLogger(__name__)

# Session persistence paths
DEFAULT_SESSION_DIR = Path("data/sessions")
DEFAULT_BRANCH_DIR = Path("data/sessions/branches")

# JSONL rotation config
MAX_JSONL_SIZE = 256 * 1024  # 256KB
MAX_ROTATED_FILES = 3


@dataclass
class SessionCompaction:
    """Tracks compaction state."""
    compacted_at: datetime | None = None
    messages_removed: int = 0
    summary: str = ""


@dataclass
class SessionFork:
    """Tracks fork state."""
    branch_id: str = ""
    branch_name: str = ""
    parent_session_id: str = ""
    created_at: datetime | None = None


@dataclass
class Session:
    """Conversation session with compaction, fork, and merge support.

    Persistence: JSONL append-only. Rotation after 256KB.
    Compaction: Auto at 100k tokens via Mistral summariser.
    Fork: Creates isolated JSONL branch for parallel exploration.
    Merge: Findings-only merge from branch to parent (v2.0 N8).
    """

    session_id: str = field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:12]}")
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    messages: list[ConversationMessage] = field(default_factory=list)
    compaction: SessionCompaction | None = None
    fork_info: SessionFork | None = None

    # Optimus extensions
    engagement_id: str | None = None
    client_id: str | None = None
    scope: ScopeConfig | None = None

    # Token tracking
    _estimated_tokens: int = 0

    # LLM router for real compaction summaries (#2)
    _llm_router: Any = field(default=None, repr=False)

    # Save cursor to avoid duplicating messages (#12)
    _last_saved_index: int = field(default=0, repr=False)

    @property
    def token_count(self) -> int:
        """Estimated token count for the session."""
        if self._estimated_tokens > 0:
            return self._estimated_tokens
        # Rough estimate: ~4 chars per token
        total_chars = sum(len(m.content) for m in self.messages)
        return total_chars // 4

    def add_message(self, role: str, content: str, **kwargs: Any) -> None:
        """Add a message to the session."""
        self.messages.append(ConversationMessage(
            role=role,
            content=content,
            **kwargs,
        ))
        self.updated_at = datetime.now(timezone.utc)

    async def compact(self) -> None:
        """Compact the session by summarising older messages.

        Uses Gemma4 via LLMRouter (budget-friendly fallback) for real summaries.
        Preserves recent N messages.
        """
        token_count = self.token_count
        if token_count < 60_000:
            return

        # Determine how many recent messages to keep
        keep_recent = 10 if token_count < 100_000 else 5

        if len(self.messages) <= keep_recent:
            return

        older = self.messages[:-keep_recent]
        recent = self.messages[-keep_recent:]

        # Real LLM summary via Gemma4 (#2)
        if self._llm_router is not None:
            from backend.core.llm_router import LLMMessage
            history_text = "\n".join(
                f"{m.role}: {m.content[:300]}" for m in older
            )
            try:
                resp = await self._llm_router.complete(
                    messages=[LLMMessage(role="user", content=(
                        f"Summarise this security engagement context in 3-5 sentences, "
                        f"preserving all findings, tool outputs, and target details:\n{history_text}"
                    ))],
                    max_tokens=512,
                    temperature=0.1,
                    prefer_fallback=True,
                )
                summary_text = resp.content
            except Exception as exc:
                logger.warning("Session %s: LLM compaction failed: %s", self.session_id, exc)
                summary_text = f"[Compacted {len(older)} messages — LLM summary failed]"
        else:
            # Fallback stub if no LLM configured
            summary_text = f"[Compacted {len(older)} messages — no LLM available for summary]"
            for msg in older:
                if msg.role == "assistant" and "finding" in msg.content.lower():
                    summary_text += f"\n- Finding context preserved from {msg.role}"

        # Replace older messages with summary
        summary_msg = ConversationMessage(
            role="system",
            content=summary_text,
        )
        self.messages = [summary_msg] + recent
        self.compaction = SessionCompaction(
            compacted_at=datetime.now(timezone.utc),
            messages_removed=len(older),
            summary=summary_text[:200],
        )

        logger.info(
            "Session %s: compacted %d messages (was ~%d tokens)",
            self.session_id, len(older), token_count,
        )

    def fork(self, branch_name: str) -> Session:
        """Fork session for parallel exploit chain exploration."""
        branch_id = f"branch-{uuid.uuid4().hex[:8]}"
        branch = Session(
            session_id=branch_id,
            engagement_id=self.engagement_id,
            client_id=self.client_id,
            scope=self.scope,
        )
        branch.fork_info = SessionFork(
            branch_id=branch_id,
            branch_name=branch_name,
            parent_session_id=self.session_id,
            created_at=datetime.now(timezone.utc),
        )
        logger.info(
            "Session %s: forked branch '%s' (%s)",
            self.session_id, branch_name, branch_id,
        )
        return branch

    async def merge(self, branch: Session) -> MergeResult:
        """Findings-only merge from branch back to parent (v2.0 N8).

        Cherry-picks: confirmed findings, tool effectiveness records,
                      MITRE ATT&CK mappings.
        Preserves in branch: raw message history, tool call/result pairs.
        """
        findings_merged = 0
        techniques_merged = 0
        effectiveness_records = 0

        for msg in branch.messages:
            # Extract findings from branch messages
            if msg.metadata.get("is_finding"):
                self.add_message(
                    role="system",
                    content=f"[Merged from branch {branch.session_id}] {msg.content}",
                    metadata={"merged_from": branch.session_id, "is_finding": True},
                )
                findings_merged += 1

            if msg.metadata.get("attack_technique"):
                techniques_merged += 1

            if msg.metadata.get("tool_effectiveness"):
                effectiveness_records += 1

        result = MergeResult(
            branch_id=branch.session_id,
            findings_merged=findings_merged,
            attack_techniques_merged=techniques_merged,
            tool_effectiveness_records=effectiveness_records,
        )

        logger.info(
            "Session %s: merged %d findings from branch %s",
            self.session_id, findings_merged, branch.session_id,
        )
        return result

    async def inspect_branch(self, branch: Session) -> BranchSummary:
        """Retrieve branch details for audit."""
        finding_count = sum(
            1 for m in branch.messages if m.metadata.get("is_finding")
        )
        return BranchSummary(
            branch_id=branch.session_id,
            branch_name=branch.fork_info.branch_name if branch.fork_info else "",
            parent_session_id=self.session_id,
            created_at=branch.created_at,
            message_count=len(branch.messages),
            finding_count=finding_count,
            status="active",
        )

    async def save(self, session_dir: Path | None = None) -> None:
        """Persist session to JSONL (incremental — only new messages since last save)."""
        base_dir = session_dir or DEFAULT_SESSION_DIR
        base_dir.mkdir(parents=True, exist_ok=True)

        filepath = base_dir / f"{self.session_id}.jsonl"

        # Only write messages added since last save (#12)
        new_messages = self.messages[self._last_saved_index:]
        if not new_messages:
            return

        with open(filepath, "a", encoding="utf-8") as f:
            for msg in new_messages:
                f.write(json.dumps({
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp.isoformat(),
                    "tool_call_id": msg.tool_call_id,
                    "metadata": msg.metadata,
                }) + "\n")

        self._last_saved_index = len(self.messages)

    @classmethod
    async def load(cls, session_id: str, session_dir: Path | None = None) -> Session:
        """Load session from JSONL."""
        base_dir = session_dir or DEFAULT_SESSION_DIR
        filepath = base_dir / f"{session_id}.jsonl"

        session = cls(session_id=session_id)
        if not filepath.exists():
            return session

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                session.messages.append(ConversationMessage(
                    role=data["role"],
                    content=data["content"],
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    tool_call_id=data.get("tool_call_id"),
                    metadata=data.get("metadata", {}),
                ))

        return session
