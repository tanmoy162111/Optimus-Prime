import asyncio
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
    async def test_create_returns_engagement_session(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        session = await store.create()
        assert isinstance(session, EngagementSession)

    async def test_create_with_engagement_id(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        session = await store.create(engagement_id="eng-abc")
        assert session.engagement_id == "eng-abc"

    async def test_resolve_returns_same_object(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        created = await store.create()
        resolved = await store.resolve(created.session_id)
        assert resolved is created

    async def test_resolve_unknown_returns_none(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        assert await store.resolve("does-not-exist") is None

    async def test_touch_updates_last_active(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        session = await store.create()
        before = session.last_active
        time.sleep(0.01)
        await store.touch(session.session_id)
        assert session.last_active > before

    async def test_touch_unknown_session_is_noop(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        await store.touch("nonexistent")  # must not raise

    async def test_multiple_sessions_are_independent(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        a = await store.create()
        b = await store.create()
        assert a.session_id != b.session_id
        a.conv_history.add_message("user", "hello")
        assert b.conv_history.messages == []

    async def test_global_instance_is_same_object(self):
        from backend.session.session_store import session_store as s1
        from backend.session.session_store import session_store as s2
        assert s1 is s2

    async def test_resolve_after_restart_reconstructs_state(self, tmp_path):
        db_path = tmp_path / "sessions.db"
        store1 = SessionStore(db_path=db_path)
        session = await store1.create()
        session.state.set_phase_status("d1", "completed")
        session.state.add_finding({"title": "finding-1"})
        await store1.save(session)
        await store1.close()

        # Simulated restart: a brand-new SessionStore instance, empty cache,
        # pointed at the same db_path.
        store2 = SessionStore(db_path=db_path)
        resolved = await store2.resolve(session.session_id)

        assert resolved is not None
        assert resolved.state.phase_status == {"d1": "completed"}
        assert resolved.state.findings == [{"title": "finding-1"}]

    async def test_journal_mode_is_wal(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        await store.initialize()
        row = await asyncio.to_thread(
            lambda: store._conn.execute("PRAGMA journal_mode").fetchone()
        )
        assert row[0].lower() == "wal"

    async def test_initialize_creates_db_file(self, tmp_path):
        db_path = tmp_path / "nested" / "sessions.db"
        store = SessionStore(db_path=db_path)
        await store.initialize()
        assert db_path.exists()
