---
phase: 02-security-hardening
plan: 03
subsystem: database
tags: [sqlite, wal, durability, pragma, client_profile, research_kb]

# Dependency graph
requires:
  - phase: 01-cleanup-configuration
    provides: tests/memory/ and tests/intelligence/ canonical test layout, backend/memory/client_profile.py and backend/intelligence/research_kb.py migrated and unified
provides:
  - "PRAGMA journal_mode=WAL + PRAGMA synchronous=NORMAL applied on ClientProfileDB connect"
  - "PRAGMA journal_mode=WAL + PRAGMA synchronous=NORMAL applied on ResearchKB connect"
  - "DATA-01 satisfied: journal_mode reads back as wal for both DB classes"
affects: [phase-3-orchestration-upgrade]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-connection PRAGMA reissue: journal_mode is file-persistent (set once), synchronous is per-connection (must reissue every new connection) — both classes open exactly one connection per process, so applying once in initialize() satisfies DATA-01"

key-files:
  created:
    - tests/intelligence/test_research_kb_wal.py
  modified:
    - backend/memory/client_profile.py
    - backend/intelligence/research_kb.py
    - tests/memory/test_client_profile.py

key-decisions:
  - "Worktree branch was stale (forked before all of Phase 1 + Phase 2 planning commits landed on main, with zero unique commits of its own) — fast-forwarded to main via `git merge --ff-only main` before starting work, since the branch had no divergent history and was a pure ancestor of main"
  - "Built a throwaway local .venv (gitignored) with unpinned fastapi/pydantic to work around system Python 3.14 lacking prebuilt wheels for pinned pydantic-core 2.9.2 (pyo3 does not yet support 3.14) — used only for local test verification, not committed"

patterns-established:
  - "Pattern 3 from RESEARCH.md applied verbatim in both files: PRAGMA journal_mode=WAL and PRAGMA synchronous=NORMAL immediately after row_factory assignment, before executescript"

requirements-completed: [DATA-01]

# Metrics
duration: 25min
completed: 2026-08-29
---

# Phase 2 Plan 3: SQLite WAL Mode Hardening Summary

**PRAGMA journal_mode=WAL + PRAGMA synchronous=NORMAL applied immediately after connect() in both ClientProfileDB and ResearchKB, with RED/GREEN TDD tests proving journal_mode reads back as "wal".**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-08-28T23:00:00Z (approx, after worktree fast-forward)
- **Completed:** 2026-08-28T23:03:13Z
- **Tasks:** 2 completed
- **Files modified:** 4 (2 source, 2 test — 1 new, 1 extended)

## Accomplishments
- `ClientProfileDB.initialize()` and `ResearchKB.initialize()` both apply `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` immediately after `row_factory` assignment, before `executescript()`
- New `tests/intelligence/test_research_kb_wal.py` and extended `tests/memory/test_client_profile.py::TestClientProfileWAL` prove `journal_mode` reads back as `"wal"` via real temp-file sqlite connections (no mocks)
- Full `tests/intelligence/` + `tests/memory/` suite green: 68 passed, 15 xfailed (pre-existing stubs unrelated to this plan), 0 regressions

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1: Add WAL tests (extend ClientProfile, new ResearchKB WAL test)** - `e44895d` (test)
2. **Task 2: Apply WAL + synchronous pragmas in both DB classes** - `d3e7d40` (feat)

_TDD gate sequence verified: `test(02-03)` commit exists before `feat(02-03)` commit; RED phase confirmed the new WAL assertion failed with `assert 'delete' == 'wal'` prior to the pragma insertion._

## Files Created/Modified
- `backend/memory/client_profile.py` - Inserted 2 PRAGMA statements + comment in `initialize()`, between `row_factory` and `executescript`
- `backend/intelligence/research_kb.py` - Same 2 PRAGMA statements + comment, identical insertion point
- `tests/memory/test_client_profile.py` - Added `TestClientProfileWAL::test_journal_mode_is_wal`
- `tests/intelligence/test_research_kb_wal.py` - New file, mirrors the ClientProfileDB WAL test pattern for ResearchKB

## Decisions Made
- **Worktree base was stale.** At start, `git rev-parse HEAD` showed this worktree's branch (`worktree-agent-a22b6b938bcac6ce7`) forked from commit `7f9efad`, which predates all of Phase 1's cleanup work (dead-code deletion, `tests/` migration) and all of Phase 2's planning docs (CONTEXT/RESEARCH/PATTERNS). `git merge-base --is-ancestor HEAD main` confirmed HEAD was a pure ancestor of `main` with zero unique commits — a safe fast-forward, not a divergent-history risk. Ran `git merge --ff-only main` to bring the worktree to `main`'s tip (`73c9ecf`) before any task work began. Without this, the plan's target test paths (`tests/memory/`, `tests/intelligence/`) would not have existed and `pyproject.toml` would still point `testpaths` at the deleted `backend/tests/`.
- **Local test venv.** System Python is 3.14; the pinned `pydantic==2.9.2` has no prebuilt wheel for 3.14 and its `pydantic-core` fails to build from source (pyo3 doesn't yet support 3.14). Created a gitignored `.venv/` and installed unpinned `fastapi`/`pydantic`/etc. purely to unblock local `pytest` collection (root `tests/conftest.py` imports `fastapi`, which breaks all collection if unavailable). This does not affect the committed source — it's a local verification aid, consistent with 02-RESEARCH.md's noted fallback ("run tests inside the backend Docker container or a project venv").

## Deviations from Plan

None beyond the worktree fast-forward and local venv setup documented above (both classified as environment/tooling fixes required to execute the plan at all, not scope changes to the plan's deliverables).

## Issues Encountered
- Stale worktree branch (see Decisions Made) — resolved via fast-forward merge, zero risk since branch had no unique commits.
- System Python 3.14 incompatible with pinned `pydantic-core` wheel — resolved via local unpinned venv for test execution only.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- DATA-01 satisfied for both currently-orphaned SQLite classes (`ClientProfileDB`, `ResearchKB`); per D-06/D-07 these stay unwired to the live orchestrator path this phase — real session persistence (`session_store.py`) remains Phase 3's PERSIST-01, untouched here.
- No blockers for other Phase 2 plans (02-01 sandbox, 02-02 SSH workdir scoping, 02-04 VerificationLoop) — this plan touched only `backend/memory/client_profile.py`, `backend/intelligence/research_kb.py`, and their tests, disjoint from the other three plans' files.

---
*Phase: 02-security-hardening*
*Completed: 2026-08-29*
