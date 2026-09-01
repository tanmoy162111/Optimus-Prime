"""Tests for TaskRegistry (D-10, PERSIST-01).

TaskRegistry shares SessionStore's SQLite connection (03-RESEARCH.md
Pattern 2) — these tests exercise it both standalone (Task 1: table
creation, upsert, CHECK constraint, asyncio.to_thread wrapping) and wired
into SessionStore's cold-path resolve() (Task 2: public attribute handoff,
crash-detection on restart).
"""

from __future__ import annotations

import ast
import inspect
import sqlite3

import pytest

from backend.agent.task_registry import TaskRegistry
from backend.session.session_store import SessionStore


@pytest.fixture
async def registry():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    reg = TaskRegistry(conn)
    await reg.initialize()
    yield reg
    conn.close()


class TestTaskRegistryTable:
    """Table creation / schema (Task 1)."""

    async def test_initialize_creates_table_with_composite_pk(self, registry):
        row = registry._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='task_registry'"
        ).fetchone()
        assert row is not None

    async def test_composite_pk_rejects_duplicate_insert(self, registry):
        # Raw duplicate insert (bypassing mark()'s upsert) must violate the
        # composite (session_id, directive_id) primary key.
        registry._conn.execute(
            "INSERT INTO task_registry "
            "(session_id, directive_id, agent_name, status, created_at, updated_at) "
            "VALUES ('s1', 'd1', 'ReconAgent', 'created', 'x', 'x')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            registry._conn.execute(
                "INSERT INTO task_registry "
                "(session_id, directive_id, agent_name, status, created_at, updated_at) "
                "VALUES ('s1', 'd1', 'ScanAgent', 'created', 'y', 'y')"
            )

    async def test_no_second_sqlite_connect_in_module(self):
        """No `sqlite3.connect(` call anywhere in the module's actual code
        (docstrings mentioning it as a negative example don't count)."""
        from backend.agent import task_registry as module

        tree = ast.parse(inspect.getsource(module))
        connect_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
        ]
        assert connect_calls == []


class TestTaskRegistryMark:
    """Upsert behavior + asyncio.to_thread wrapping (Task 1)."""

    async def test_mark_upserts_single_row(self, registry):
        await registry.mark("s1", "d1", "ReconAgent", "running")
        await registry.mark("s1", "d1", "ReconAgent", "completed")

        rows = registry._conn.execute(
            "SELECT status, created_at, updated_at FROM task_registry "
            "WHERE session_id = 's1' AND directive_id = 'd1'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == "completed"

    async def test_execute_calls_wrapped_in_asyncio_to_thread(self):
        """No bare `self._conn.execute(` outside an `asyncio.to_thread(...)` call."""
        from backend.agent import task_registry as module

        tree = ast.parse(inspect.getsource(module))
        direct_execute_calls: list[ast.Call] = []

        class Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.to_thread_depth = 0

            def visit_Call(self, node: ast.Call) -> None:
                is_to_thread = (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "to_thread"
                )
                if is_to_thread:
                    self.to_thread_depth += 1
                    self.generic_visit(node)
                    self.to_thread_depth -= 1
                    return

                is_conn_execute = (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "execute"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "_conn"
                )
                if is_conn_execute and self.to_thread_depth == 0:
                    direct_execute_calls.append(node)
                self.generic_visit(node)

        Visitor().visit(tree)
        assert direct_execute_calls == []


class TestTaskRegistryConstraint:
    """CHECK constraint on status (Task 1)."""

    async def test_status_check_constraint_rejects_invalid_value(self, registry):
        with pytest.raises(sqlite3.IntegrityError):
            await registry.mark("s1", "d1", "ReconAgent", "not-a-real-status")


class TestSessionStoreTaskRegistryHandoff:
    """Public attribute handoff + crash-detection on restart (Task 2)."""

    async def test_task_registry_is_public_attribute(self, tmp_path):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        await store.initialize()

        assert isinstance(store.task_registry, TaskRegistry)
        assert store.task_registry._conn is store._conn

    async def test_running_row_detected_after_restart(self, tmp_path, caplog):
        db_path = tmp_path / "sessions.db"
        store1 = SessionStore(db_path=db_path)
        session = await store1.create()
        await store1.task_registry.mark(
            session.session_id, "d1", "ReconAgent", "running"
        )
        await store1.close()

        # Simulated restart: a brand-new SessionStore instance, empty cache,
        # pointed at the same db_path.
        store2 = SessionStore(db_path=db_path)
        with caplog.at_level("ERROR"):
            resolved = await store2.resolve(session.session_id)

        assert resolved is not None
        stale = await store2.task_registry.detect_stale(session.session_id)
        assert len(stale) == 1
        assert stale[0]["directive_id"] == "d1"
        assert stale[0]["agent_name"] == "ReconAgent"
        assert any("d1" in record.message for record in caplog.records)

    async def test_no_stale_rows_resolves_normally(self, tmp_path):
        db_path = tmp_path / "sessions.db"
        store1 = SessionStore(db_path=db_path)
        session = await store1.create()
        await store1.task_registry.mark(
            session.session_id, "d1", "ReconAgent", "completed"
        )
        await store1.close()

        store2 = SessionStore(db_path=db_path)
        resolved = await store2.resolve(session.session_id)

        assert resolved is not None
        stale = await store2.task_registry.detect_stale(session.session_id)
        assert stale == []

    async def test_hot_path_cache_hit_does_not_call_detect_stale(self, tmp_path, monkeypatch):
        store = SessionStore(db_path=tmp_path / "sessions.db")
        session = await store.create()

        calls = []
        original = store.task_registry.detect_stale

        async def _tracking_detect_stale(session_id):
            calls.append(session_id)
            return await original(session_id)

        monkeypatch.setattr(store.task_registry, "detect_stale", _tracking_detect_stale)

        resolved = await store.resolve(session.session_id)

        assert resolved is session
        assert calls == []
