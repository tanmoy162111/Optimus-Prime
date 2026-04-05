"""Suite 1 — Session.merge() tests (N8, T5).

Tests fork/merge lifecycle:
  - Fork creates isolated branch with independent message history
  - Findings-only merge: only is_finding messages cherry-picked
  - Attack techniques and tool effectiveness records merged
  - Raw message history stays in branch
  - JSONL save/load round-trip works
"""

from __future__ import annotations

import pytest

from backend.core.session import Session


class TestSessionFork:
    """Fork creates isolated branches."""

    def test_fork_creates_new_session(self):
        parent = Session()
        parent.add_message("user", "Start pentest")
        branch = parent.fork("exploit-chain-1")

        assert branch.session_id != parent.session_id
        assert branch.fork_info is not None
        assert branch.fork_info.parent_session_id == parent.session_id
        assert branch.fork_info.branch_name == "exploit-chain-1"

    def test_fork_is_isolated(self):
        """Messages added to branch do not appear in parent."""
        parent = Session()
        parent.add_message("user", "Start pentest")

        branch = parent.fork("test-branch")
        branch.add_message("assistant", "Branch-only message")

        assert len(parent.messages) == 1
        assert len(branch.messages) == 1
        assert branch.messages[0].content == "Branch-only message"

    def test_fork_inherits_engagement_metadata(self):
        parent = Session(engagement_id="eng-001", client_id="client-001")
        branch = parent.fork("test")

        assert branch.engagement_id == "eng-001"
        assert branch.client_id == "client-001"


class TestSessionMerge:
    """Findings-only merge from branch to parent (N8)."""

    @pytest.mark.asyncio
    async def test_merge_findings_only(self):
        """Only is_finding messages are merged to parent."""
        parent = Session()
        parent.add_message("user", "Start pentest")

        branch = parent.fork("exploit-chain")
        # Non-finding message
        branch.add_message("assistant", "Running sqlmap...", metadata={"tool": "sqlmap"})
        # Finding message
        branch.add_message(
            "assistant",
            "SQL injection found on /login endpoint",
            metadata={"is_finding": True, "severity": "high"},
        )
        # Another non-finding
        branch.add_message("assistant", "Tool output: ...", metadata={"tool_output": True})
        # Another finding
        branch.add_message(
            "assistant",
            "XSS vulnerability in search parameter",
            metadata={"is_finding": True, "severity": "medium"},
        )

        result = await parent.merge(branch)

        assert result.findings_merged == 2
        assert result.branch_id == branch.session_id
        # Parent should have original message + 2 merged findings
        assert len(parent.messages) == 3  # 1 original + 2 merged

    @pytest.mark.asyncio
    async def test_merged_messages_tagged_with_source(self):
        """Merged messages contain branch source info."""
        parent = Session()
        branch = parent.fork("chain-1")
        branch.add_message(
            "assistant", "Finding content",
            metadata={"is_finding": True},
        )

        await parent.merge(branch)

        merged = [m for m in parent.messages if m.metadata.get("merged_from")]
        assert len(merged) == 1
        assert merged[0].metadata["merged_from"] == branch.session_id

    @pytest.mark.asyncio
    async def test_attack_techniques_counted(self):
        """Attack technique records are counted in merge result."""
        parent = Session()
        branch = parent.fork("exploit")
        branch.add_message(
            "assistant", "ATT&CK: T1190",
            metadata={"attack_technique": "T1190"},
        )
        branch.add_message(
            "assistant", "ATT&CK: T1059",
            metadata={"attack_technique": "T1059"},
        )

        result = await parent.merge(branch)
        assert result.attack_techniques_merged == 2

    @pytest.mark.asyncio
    async def test_tool_effectiveness_counted(self):
        """Tool effectiveness records are counted."""
        parent = Session()
        branch = parent.fork("scan")
        branch.add_message(
            "assistant", "nuclei found 3 vulns",
            metadata={"tool_effectiveness": {"tool": "nuclei", "findings": 3}},
        )

        result = await parent.merge(branch)
        assert result.tool_effectiveness_records == 1

    @pytest.mark.asyncio
    async def test_raw_history_stays_in_branch(self):
        """Non-finding messages remain only in branch after merge."""
        parent = Session()
        branch = parent.fork("test")
        branch.add_message("assistant", "Running nmap...", metadata={"tool": "nmap"})
        branch.add_message("assistant", "Finding!", metadata={"is_finding": True})
        branch.add_message("assistant", "Cleanup output", metadata={})

        await parent.merge(branch)

        # Branch still has all 3 messages
        assert len(branch.messages) == 3
        # Parent only has the 1 finding
        assert len(parent.messages) == 1

    @pytest.mark.asyncio
    async def test_merge_empty_branch(self):
        """Merging an empty branch produces zero findings."""
        parent = Session()
        branch = parent.fork("empty")

        result = await parent.merge(branch)
        assert result.findings_merged == 0
        assert result.status == "completed"


class TestSessionInspectBranch:
    """Branch inspection for audit."""

    @pytest.mark.asyncio
    async def test_inspect_branch(self):
        parent = Session()
        branch = parent.fork("audit-test")
        branch.add_message("assistant", "Finding", metadata={"is_finding": True})
        branch.add_message("assistant", "Not a finding", metadata={})

        summary = await parent.inspect_branch(branch)

        assert summary.branch_id == branch.session_id
        assert summary.branch_name == "audit-test"
        assert summary.message_count == 2
        assert summary.finding_count == 1


class TestSessionPersistence:
    """JSONL save/load round-trip."""

    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path):
        """Session survives save/load cycle."""
        session = Session(engagement_id="eng-test")
        session.add_message("user", "Hello")
        session.add_message("assistant", "Hi there", metadata={"key": "value"})

        await session.save(session_dir=tmp_path)
        loaded = await Session.load(session.session_id, session_dir=tmp_path)

        assert loaded.session_id == session.session_id
        assert len(loaded.messages) == 2
        assert loaded.messages[0].role == "user"
        assert loaded.messages[1].metadata.get("key") == "value"

    @pytest.mark.asyncio
    async def test_load_nonexistent_returns_empty(self, tmp_path):
        """Loading a nonexistent session returns empty session."""
        loaded = await Session.load("nonexistent", session_dir=tmp_path)
        assert len(loaded.messages) == 0


class TestSessionCompaction:
    """Auto-compaction at token thresholds."""

    @pytest.mark.asyncio
    async def test_compact_below_threshold_noop(self):
        """No compaction when below 60k tokens."""
        session = Session()
        session.add_message("user", "Short message")
        await session.compact()
        assert session.compaction is None

    @pytest.mark.asyncio
    async def test_compact_reduces_messages(self):
        """Compaction at high token count reduces message count."""
        session = Session()
        # Add enough messages to exceed 60k tokens (~240k chars)
        for i in range(100):
            session.add_message("assistant", "x" * 3000, metadata={})

        session._estimated_tokens = 70_000  # Force above threshold
        await session.compact()

        assert session.compaction is not None
        # Should have summary + 10 recent messages
        assert len(session.messages) == 11
