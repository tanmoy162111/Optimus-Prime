---
phase: 03-orchestration-upgrade
plan: 04
subsystem: directive-handoff-state
tags: [sqlite, wal, task-registry, crash-detection, persist-01, d-10]
requires:
  - Phase 3 Plan 03 SQLite+WAL SessionStore (backend/session/session_store.py)
provides:
  - TaskRegistry (backend/agent/task_registry.py) — directive handoff state store
  - session_store.task_registry public attribute (single shared instance)
  - Crash-detection on cold-path resolve (restart recovery)
affects:
  - backend/session/session_store.py
tech-stack:
  added: []
  patterns:
    - Shared sqlite3.Connection between SessionStore and TaskRegistry (no second sqlite3.connect()/db file)
    - asyncio.to_thread wrapping for all sqlite3 calls (no bare self._conn.execute in async def)
    - AST-based static verification tests (no second connect, no unwrapped execute)
key-files:
  created:
    - backend/agent/task_registry.py
    - tests/agent/test_task_registry.py
  modified:
    - backend/session/session_store.py
    - .planning/phases/03-orchestration-upgrade/deferred-items.md
decisions:
  - "TaskRegistry never opens its own sqlite3.connect() — constructor takes a required shared connection, bound by SessionStore.initialize() to its own self._conn (RESEARCH.md Pattern 2), making cross-table divergence after a crash structurally impossible rather than merely unlikely"
  - "session_store.task_registry is the single public attribute Plan 09's Orchestrator reads — no alternative construct-your-own path exists in the codebase"
  - "Stale ('running') directives detected on cold-path resolve are logged at ERROR and surfaced via a dynamic session.stale_directives list, never auto-marked completed — halting is left to the caller (OmO/Orchestrator, Plan 08/09) per AI-SPEC Section 6"
  - "detect_stale() only runs on the cache-miss (restart-recovery) branch of resolve() — the hot path (cache hit) does not pay this I/O cost, matching SessionStore's existing hot/cold split"
metrics:
  duration: ~35min
  completed: 2026-09-01
---

# Phase 3 Plan 04: TaskRegistry (Directive Handoff State) Summary

TaskRegistry now persists directive-level handoff state (created/running/completed/failed) on SessionStore's shared SQLite connection, and SessionStore exposes it as the single `session_store.task_registry` public attribute — with crash-mid-directive detection wired into the cold-path (restart-recovery) `resolve()`.

## What Was Built

**Task 1 — `TaskRegistry` sharing SessionStore's connection:** `backend/agent/task_registry.py` follows `ClientProfileDB`'s CRUD-store shape but takes a **required shared `sqlite3.Connection`** in `__init__` rather than opening its own — RESEARCH.md Pattern 2's core requirement, since a second `sqlite3.connect()`/`.db` file would reintroduce the exact "TaskRegistry disagrees with phase_status after a crash" ambiguity the table exists to eliminate. `initialize()` sets `row_factory = sqlite3.Row`, reissues the WAL pragma pair (idempotent), and `executescript`s the verbatim `task_registry` table (composite PK on `session_id`+`directive_id`, `status` CHECK constraint) and session index from RESEARCH.md. `mark()` upserts via `INSERT ... ON CONFLICT(session_id, directive_id) DO UPDATE`, timestamped with timezone-aware UTC ISO strings. `detect_stale()` runs the verbatim crash-detection query (`SELECT directive_id, agent_name FROM task_registry WHERE session_id = ? AND status = 'running'`). Every blocking sqlite3 call is wrapped in `asyncio.to_thread` — verified both by behavioral tests and an AST-based static check that walks the module for any `self._conn.execute(` call not nested inside an `asyncio.to_thread(...)` call (correctly handles the `asyncio.to_thread(self._conn.execute, ...)` direct-reference form and the `asyncio.to_thread(lambda: self._conn.execute(...).fetchone())` lambda form used elsewhere in this codebase).

**Task 2 — `session_store.task_registry` public attribute + crash-detection wiring:** `SessionStore.__init__` now defaults `self.task_registry = None`; `initialize()` constructs the single `TaskRegistry(self._conn)` instance immediately after the sessions table is created and calls `await self.task_registry.initialize()`. This is the one shared instance — Plan 09's `Orchestrator` is documented (03-09-PLAN.md) to read `session_store.task_registry` directly, never constructing its own. `resolve()`'s cold-path branch (cache miss — i.e., restart recovery, reached only after a fresh SQLite read of `EngagementSession.from_row()`) now calls `await self.task_registry.detect_stale(session_id)`; any `'running'` row is logged at `ERROR` (naming the stale `directive_id` + `agent_name`, per AI-SPEC Section 6's "any session-resume mismatch → ERROR, halt further dispatch") and the full stale set is attached to the reconstructed session as a dynamic `session.stale_directives` list (not a dataclass field — `EngagementSession` is a plain, non-frozen dataclass, so this is a safe ad hoc attachment) so a future caller (Plan 08/09's OmO) can act on it without needing to re-query. Stale directives are never auto-marked completed. The hot path (in-memory cache hit, returned before any of this code runs) is unaffected — confirmed by a monkeypatch test asserting `detect_stale` is never called on a resident session.

## Deviations from Plan

None — plan executed as written. The plan's TDD RED/GREEN gate required temporarily reverting `session_store.py` to its pre-Task-2 state (and moving `task_registry.py` aside for Task 1) to produce genuinely-failing RED commits before restoring the implementation for GREEN — this is standard TDD executor mechanics, not a deviation from the plan's content.

## TDD Gate Compliance

Both tasks used `tdd="true"`. Gate sequence verified in git log:
- Task 1: RED `44c1890` (`test(03-04): add failing tests for TaskRegistry table/mark/constraint`) → GREEN `1a8281a` (`feat(03-04): implement TaskRegistry sharing SessionStore's SQLite connection`)
- Task 2: RED `a8f95c4` (`test(03-04): add failing tests for session_store.task_registry handoff`) → GREEN `ad863e1` (`feat(03-04): expose session_store.task_registry + wire crash-detection`)

Both RED commits were confirmed to fail before their corresponding GREEN commit landed: Task 1's RED failed at collection (`ModuleNotFoundError`-equivalent — `backend/agent/task_registry.py` did not exist); Task 2's RED failed with `AttributeError: 'SessionStore' object has no attribute 'task_registry'` (verified against `session_store.py` temporarily reverted to its pre-Task-2 state, then restored for GREEN).

## Verification

- `pytest tests/agent/test_task_registry.py tests/session/ -x --tb=short` — 37 passed
- `pytest tests/agent/test_task_registry.py -k "mark or table or constraint" -x --tb=short` — 6 passed (Task 1's exact verify command)
- `pytest tests/agent/test_task_registry.py::test_running_row_detected_after_restart tests/agent/test_task_registry.py::test_task_registry_is_public_attribute tests/session/test_session_store.py -x --tb=short` — all passed (Task 2's exact verify command, run via class-qualified node IDs since these tests live in classes)
- `python -c "from backend.agent.task_registry import TaskRegistry"` — imports clean
- Full suite (`pytest tests/ --ignore=tests/tools/test_sandbox_docker.py`) — 197 passed, 2 skipped, 15 xfailed, 1 pre-existing failure (`test_chat_without_token_returns_401` — already documented in `deferred-items.md` by Plans 03-01/03-07, unrelated to `task_registry.py`/`session_store.py`; independently re-observed and logged here, not fixed, per scope-boundary rules)
- No bare `self._conn.execute(` outside `asyncio.to_thread(...)` in `task_registry.py` (AST-verified by `test_execute_calls_wrapped_in_asyncio_to_thread`)
- No `sqlite3.connect` call anywhere in `task_registry.py`'s actual code (AST-verified by `test_no_second_sqlite_connect_in_module`, distinguishing real calls from the docstring's mention of the pattern it avoids)

## Known Stubs

None.

## Threat Flags

None — this plan's only new surface (the `task_registry` table + `detect_stale` query) is exactly the mitigation the plan's own threat model (T-03-05, T-03-05c) already covers; no unmodeled surface introduced.

## Self-Check: PASSED

- FOUND: backend/agent/task_registry.py
- FOUND: tests/agent/test_task_registry.py
- FOUND: backend/session/session_store.py (task_registry public attribute + cold-path detect_stale wiring present)
- FOUND commit 44c1890
- FOUND commit 1a8281a
- FOUND commit a8f95c4
- FOUND commit ad863e1
- FOUND commit c1e55ed
