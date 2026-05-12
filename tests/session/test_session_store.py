import time
import pytest

from backend.session.engagement_session import EngagementSession
from backend.session.session_store import SessionStore


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
