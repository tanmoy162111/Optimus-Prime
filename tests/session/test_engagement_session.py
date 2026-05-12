import pytest
from datetime import datetime

from backend.session.engagement_session import (
    ConversationHistory,
    EngagementSession,
    EngagementState,
    ScopeConfig,
)


class TestConversationHistory:
    def test_starts_empty(self):
        h = ConversationHistory()
        assert h.messages == []

    def test_add_message_appends(self):
        h = ConversationHistory()
        h.add_message("user", "hello")
        assert len(h.messages) == 1
        assert h.messages[0] == {"role": "user", "content": "hello"}

    def test_get_context_window_returns_all_when_few(self):
        h = ConversationHistory()
        h.add_message("user", "a")
        h.add_message("assistant", "b")
        window = h.get_context_window()
        assert len(window) == 2

    def test_get_context_window_caps_at_40(self):
        h = ConversationHistory()
        for i in range(50):
            h.add_message("user", f"msg {i}")
        window = h.get_context_window()
        assert len(window) == 40

    def test_get_context_window_returns_most_recent(self):
        h = ConversationHistory()
        for i in range(50):
            h.add_message("user", f"msg {i}")
        window = h.get_context_window()
        assert window[-1]["content"] == "msg 49"
        assert window[0]["content"] == "msg 10"


class TestScopeConfig:
    def test_defaults(self):
        s = ScopeConfig()
        assert s.targets == []
        assert s.exclusions == []
        assert s.stealth_level == "medium"
        assert s.ports == []
        assert s.protocols == []

    def test_accepts_targets(self):
        s = ScopeConfig(targets=["192.168.1.1"], stealth_level="low")
        assert s.targets == ["192.168.1.1"]
        assert s.stealth_level == "low"


class TestEngagementState:
    def test_defaults(self):
        s = EngagementState()
        assert s.phase_status == {}
        assert s.findings == []
        assert s.gate_queue == []

    def test_add_finding(self):
        s = EngagementState()
        s.add_finding({"severity": "HIGH", "title": "SQLi"})
        assert len(s.findings) == 1
        assert s.findings[0]["title"] == "SQLi"

    def test_set_phase_status(self):
        s = EngagementState()
        s.set_phase_status("recon", "RUNNING")
        assert s.phase_status["recon"] == "RUNNING"


class TestEngagementSession:
    def test_create_factory(self):
        session = EngagementSession.create()
        assert session.session_id is not None
        assert session.engagement_id is not None
        assert isinstance(session.conv_history, ConversationHistory)
        assert isinstance(session.state, EngagementState)
        assert isinstance(session.scope, ScopeConfig)
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_active, datetime)

    def test_create_with_engagement_id(self):
        session = EngagementSession.create(engagement_id="eng-123")
        assert session.engagement_id == "eng-123"

    def test_two_sessions_have_different_ids(self):
        a = EngagementSession.create()
        b = EngagementSession.create()
        assert a.session_id != b.session_id
        assert a.engagement_id != b.engagement_id
