---
phase: 03-orchestration-upgrade
plan: 03
subsystem: session-persistence
tags: [sqlite, wal, session-store, persistence, async]
requires:
  - Phase 2 SQLite WAL pattern (backend/memory/client_profile.py)
provides:
  - EngagementSession.to_row()/from_row() serialization
  - Async SQLite + WAL backed SessionStore (cache-plus-persistence)
affects:
  - backend/api/ws_handler.py
  - backend/api/chat_routes.py
  - backend/app.py
tech-stack:
  added: []
  patterns:
    - Cache-plus-persistence store (in-memory dict hot path, SQLite cold path)
    - asyncio.to_thread wrapping for all sqlite3 calls (no bare self._conn.execute in async def)
key-files:
  created: []
  modified:
    - backend/session/engagement_session.py
    - backend/session/session_store.py
    - backend/api/ws_handler.py
    - backend/api/chat_routes.py
    - backend/app.py
    - .gitignore
    - tests/session/test_session_store.py
decisions:
  - "session_store.initialize()/close() wired into backend/app.py's existing lifespan hooks (startup/shutdown), not lazy-on-first-call"
  - "chat_routes.py (outside plan's files_modified list) also awaited — SessionStore's async conversion breaks it directly (Rule 3 blocking issue)"
  - ".gitignore data/*.db glob didn't match nested data/sessions/sessions.db — extended with data/**/*.db and data/**/*.sqlite (Rule 2)"
metrics:
  duration: 6min
  completed: 2026-09-01
---

# Phase 3 Plan 03: Session Persistence (PERSIST-01) Summary

EngagementSession now serializes losslessly to JSON (including datetime fields), and SessionStore is a SQLite+WAL cache-plus-persistence store — matching Phase 2's ClientProfileDB/ResearchKB pattern — that survives a process restart while preserving in-memory object identity on the hot path.

## What Was Built

**Task 1 — `EngagementSession.to_row()`/`from_row()`:** `to_row()` serializes via `json.dumps(dataclasses.asdict(self), default=str)`, letting `default=str` convert the `created_at`/`last_active` datetime fields to ISO strings (RESEARCH.md Pitfall 4 — a naive `json.dumps(asdict(...))` raises `TypeError` without this). `from_row()` explicitly reconstructs `ScopeConfig`, `ConversationHistory`, and `EngagementState` from the parsed dict rather than assuming the JSON round-trips back into dataclass instances automatically, and parses the two datetime fields back via `datetime.fromisoformat`.

**Task 2 — SQLite + WAL `SessionStore`:** Rewrote `SessionStore` as cache-plus-persistence (RESEARCH.md Pitfall 3's recommended model). The in-memory `Dict[str, EngagementSession]` remains the hot path — `resolve()` returns the exact same object on a cache hit, preserving identity for `ws_handler.py`'s per-message resolve pattern. On a cache miss (e.g., after a restart), `resolve()` reads `SELECT payload FROM sessions WHERE session_id=?` via `asyncio.to_thread`, deserializes with `EngagementSession.from_row()`, and repopulates the cache. `initialize()` follows `ClientProfileDB`'s exact connect → `PRAGMA journal_mode=WAL` → `PRAGMA synchronous=NORMAL` → `row_factory = sqlite3.Row` sequence, all wrapped in `asyncio.to_thread`. `create()`/`resolve()`/`touch()` are now async; a new `save()` upserts `session.to_row()`. The connection is exposed as `self._conn` for Plan 04's TaskRegistry to share.

**Task 3 — awaited call sites:** `ws_handler.py`'s three `SessionStore` call sites (init-branch resolve-or-create, chat-branch resolve, touch) now `await` the async methods. The init-branch was restructured from `(resolve(...) if raw_id else None) or create()` into explicit `if not session: session = await create()` — the old `or` idiom would never fall through to `create()` since a coroutine object is always truthy. `backend/app.py`'s existing `lifespan` startup/shutdown hooks now call `session_store.initialize()`/`session_store.close()`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `chat_routes.py` broken by SessionStore's async conversion**
- **Found during:** Task 3
- **Issue:** `chat_routes.py` is not in this plan's `files_modified` list, but it calls `session_store.resolve()`/`.create()`/`.touch()` synchronously, same as the old `ws_handler.py` call sites. After Task 2's async conversion, these calls would return coroutine objects instead of `EngagementSession`, breaking the REST `/api/chat` and `/api/session/{id}` endpoints (a coroutine is always truthy, so the `or session_store.create()` fallback would never fire, and `.session_id` attribute access on a coroutine would raise `AttributeError`).
- **Fix:** Awaited the same three call sites in `chat_routes.py`, restructuring the init logic the same way as `ws_handler.py`.
- **Files modified:** `backend/api/chat_routes.py`
- **Commit:** 2737612

**2. [Rule 2 - Missing critical functionality] `.gitignore` didn't cover the new default SQLite path**
- **Found during:** Task 3 verification (full test suite run)
- **Issue:** Running the test suite exercises the real global `session_store` singleton (via `tests/api/test_auth.py`'s `TestClient` hitting `/api/chat`), which writes to the default path `data/sessions/sessions.db`. `.gitignore`'s existing `data/*.db` glob only matches direct children of `data/`, not the nested `data/sessions/sessions.db` — this file would have been picked up as untracked and risked being accidentally committed. Previously `SessionStore` was pure in-memory, so no test run ever touched disk via the default path; this task's persistence conversion introduces the risk for the first time.
- **Fix:** Added `data/**/*.db` and `data/**/*.sqlite` to `.gitignore`; removed the generated `data/` directory from the working tree.
- **Files modified:** `.gitignore`
- **Commit:** 2737612

## TDD Gate Compliance

Plan-level tasks used `tdd="true"` for Task 1 and Task 2. Gate sequence verified in git log:
- Task 1: RED `7a9245c` (test) → GREEN `d9a797e` (feat)
- Task 2: RED `e25f67d` (test) → GREEN `c2f229c` (feat)

Both RED commits were confirmed to fail before their corresponding GREEN commit landed (`AttributeError: 'EngagementSession' object has no attribute 'to_row'` for Task 1; `TypeError: SessionStore.__init__() got an unexpected keyword argument 'db_path'` for Task 2).

## Verification

- `pytest tests/session/ -x --tb=short` — 27 passed
- `python -c "import backend.api.ws_handler"` — imports without error
- `python -c "import backend.app"` / `import backend.api.chat_routes"` — import without error
- Full suite (`pytest tests/ --ignore=tests/tools/test_sandbox_docker.py`) — 159 passed, 2 skipped, 15 xfailed (pre-existing, unrelated to this plan; `test_sandbox_docker.py` fails collection in this environment due to a missing `docker` package, unrelated to session persistence)
- `PRAGMA journal_mode` confirmed to report `wal` (`test_journal_mode_is_wal`)
- No bare `self._conn.execute(...)` outside `asyncio.to_thread` (grep-verified)

## Known Stubs

None.

## Self-Check: PASSED

- FOUND: backend/session/engagement_session.py (to_row/from_row present)
- FOUND: backend/session/session_store.py (SQLite + WAL implementation present)
- FOUND: backend/api/ws_handler.py (await session_store.resolve present)
- FOUND: backend/api/chat_routes.py (await session_store.resolve present)
- FOUND: backend/app.py (session_store.initialize/close wired into lifespan)
- FOUND commit 7a9245c
- FOUND commit d9a797e
- FOUND commit e25f67d
- FOUND commit c2f229c
- FOUND commit 2737612
