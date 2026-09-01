import time
from datetime import datetime

import pytest

from backend.session.engagement_session import EngagementSession
from backend.session.session_store import SessionStore


class TestEngagementSessionSerialization:
    def test_round_trip_preserves_data(self):
        session = EngagementSession.create()
        session.scope.targets = ["10.0.0.1"]
        session.conv_history.add_message("user", "hello")
        session.conv_history.add_message("assistant", "hi")
        session.state.set_phase_status("d1", "completed")
        session.state.add_finding({"title": "SQLi"})

        payload = session.to_row()
        restored = EngagementSession.from_row(payload)

        assert restored.scope == session.scope
        assert restored.conv_history.messages == session.conv_history.messages
        assert restored.state.phase_status == session.state.phase_status
        assert restored.state.findings == session.state.findings

    def test_round_trip_preserves_datetime_types(self):
        session = EngagementSession.create()
        payload = session.to_row()
        restored = EngagementSession.from_row(payload)
        assert isinstance(restored.created_at, datetime)
        assert isinstance(restored.last_active, datetime)
        assert restored.created_at == session.created_at
        assert restored.last_active == session.last_active

    def test_to_row_returns_str_and_does_not_raise(self):
        session = EngagementSession.create()
        payload = session.to_row()
        assert isinstance(payload, str)


class TestSessionStore:
    def test_create_returns_engagement_session(self):
        store = SessionStore()
        session = store.create()
        assert isinstance(session, EngagementSession)

    def test_create_with_engagement_id(self):
        store = SessionStore()
        session = store.create(engagement_id="eng-abc")
        assert session.engagement_id == "eng-abc"

    def test_resolve_returns_same_object(self):
        store = SessionStore()
        created = store.create()
        resolved = store.resolve(created.session_id)
        assert resolved is created

    def test_resolve_unknown_returns_none(self):
        store = SessionStore()
        assert store.resolve("does-not-exist") is None

    def test_touch_updates_last_active(self):
        store = SessionStore()
        session = store.create()
        before = session.last_active
        time.sleep(0.01)
        store.touch(session.session_id)
        assert session.last_active > before

    def test_touch_unknown_session_is_noop(self):
        store = SessionStore()
        store.touch("nonexistent")  # must not raise

    def test_multiple_sessions_are_independent(self):
        store = SessionStore()
        a = store.create()
        b = store.create()
        assert a.session_id != b.session_id
        a.conv_history.add_message("user", "hello")
        assert b.conv_history.messages == []

    def test_global_instance_is_same_object(self):
        from backend.session.session_store import session_store as s1
        from backend.session.session_store import session_store as s2
        assert s1 is s2
