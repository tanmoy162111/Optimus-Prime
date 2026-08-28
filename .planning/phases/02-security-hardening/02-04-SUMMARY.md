---
phase: 02-security-hardening
plan: 04
subsystem: verification
tags: [verification-loop, data-02, engagement-scoping, tdd]
dependency-graph:
  requires: [backend/verification/verification_policy.py]
  provides: [backend/verification/verification_loop.py (scoping-only stub)]
  affects: []
tech-stack:
  added: []
  patterns: ["constructor-injected policy dependency (policy | None = None -> self._policy = policy or DEFAULT)"]
key-files:
  created:
    - backend/verification/verification_loop.py
    - tests/verification/__init__.py
    - tests/verification/test_verification_loop.py
  modified: []
decisions:
  - "Fast-forward-merged worktree branch onto main before executing (see Deviations) — worktree was created from a stale pre-Phase-1 base"
  - "VerificationLoop.check_and_increment(engagement_id, finding_id) keeps the two IDs as separate arguments so v1.1 Phase 5 can add verify_finding(...) without a signature migration"
metrics:
  duration: "~25min"
  completed: "2026-08-29"
---

# Phase 2 Plan 4: VerificationLoop Scoping Stub Summary

Minimal engagement-scoped `VerificationLoop` stub that fixes the cross-engagement verification-budget bleed bug (DATA-02) by keying `_request_counts` on `f"{engagement_id}:{finding_id}"` instead of bare `finding_id`.

## What Was Built

- `backend/verification/verification_loop.py` (new): `VerificationLoop` class consuming `VerificationPolicy` (from `backend/verification/verification_policy.py`) as an injected constructor dependency. Exposes `check_and_increment(engagement_id, finding_id) -> bool`, incrementing and checking a per-`{engagement_id}:{finding_id}` counter against `VerificationPolicy.max_requests_per_finding` (default 3). Deliberately excludes CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW classification, OmO Reviewer role, and verification tool dispatch — all deferred to v1.1 Phase 5 per D-09.
- `tests/verification/test_verification_loop.py` (new): three unit tests — default-policy budget exhaustion (3 True, 4th False), cross-engagement isolation (same `finding_id`, different `engagement_id`s keep independent budgets), and injected custom-policy honoring (`VerificationPolicy(max_requests_per_finding=1)`).
- `tests/verification/__init__.py` (new): package marker.

Followed the plan's TDD sequence: Task 1 wrote the test file first (RED — module didn't exist, confirmed via `ModuleNotFoundError` on collection), Task 2 implemented the stub (GREEN — all 3 tests pass).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] Worktree branch was created from a stale pre-Phase-1 base**
- **Found during:** Initial state inspection, before Task 1
- **Issue:** `git log`/`git worktree list` showed this worktree's branch (`worktree-agent-ab0ede5924818f60a`) was at commit `7f9efad`, 30 commits behind `main` (`73c9ecf`) and 0 commits ahead — i.e. a strict ancestor. This predates all of Phase 1's cleanup: `backend/core/`, `backend/agents/`, `backend/main.py`, and the old `backend/tests/` directory (including a stale, buggy `backend/verification/verification_loop.py` that imported from the since-deleted `backend.core.models`/`backend.core.xai_logger` and keyed its counter by bare `finding_id` — literally the DATA-02 bug this plan exists to fix) were all still present. Sibling worktrees for plans 02-01/02-02/02-03 were correctly branched from `main`'s tip (`73c9ecf`); only this one was stale.
- **Fix:** Ran `git merge --ff-only main`, a pure fast-forward (safe — no divergent commits to reconcile, no history rewrite, no destructive operation). This brought the worktree to `main`'s tip, correctly removing the stale `backend/verification/verification_loop.py` (and other Phase-1-deleted files) so Task 2 could create the file fresh per the plan's target design.
- **Files affected:** none directly (this was a branch-catch-up, not a content edit) — 111 files changed via the fast-forward, matching Phase 1's already-completed and previously-reviewed cleanup diff.
- **Verification:** confirmed post-merge that `backend/verification/` contained only `__init__.py` and `verification_policy.py` (no stale `verification_loop.py`), and that `backend/core`, `backend/agents`, `backend/main.py` were absent, matching Phase 1's SUMMARY claims.
- **Commit:** no separate commit (fast-forward moved the branch pointer only; no new commit object was created by this operation).

### Environment Note (not a deviation, no code impact)

The sandboxed dev host has no project venv and system Python is 3.14 (pinned `pydantic-core`/`tiktoken` wheels in `backend/requirements.txt` fail to build against 3.14 — `pyo3` only supports up to 3.13). Per `02-RESEARCH.md`'s own "Environment Availability" note (tests should run inside the backend Docker container or a project venv), I created a throwaway venv at `/tmp/claude-1000/optimus-venv` with unpinned/latest versions of the runtime deps needed to satisfy `tests/conftest.py`'s `fastapi` import and the transitive import chain (`fastapi`, `pydantic`, `pydantic-settings`, `tiktoken`, `aiohttp`, `paramiko`, `python-socketio[client]`, `python-json-logger`, `pytest`, `pytest-asyncio`, `httpx`; `weasyprint` and `anthropic` intentionally skipped/not required — `anthropic` is lazily imported inside a function, `weasyprint` is not in this plan's import chain). This venv is outside the repo and not committed; it was used only to run `pytest tests/verification/test_verification_loop.py -x --tb=short`, which the plan's `<verify>` block specifies.

## Task Verification

- Task 1 (RED): `pytest tests/verification/test_verification_loop.py` failed with `ModuleNotFoundError: No module named 'backend.verification.verification_loop'` — confirmed expected RED state before Task 2.
- Task 2 (GREEN): `pytest tests/verification/test_verification_loop.py -x --tb=short` → 3 passed.
- All plan `acceptance_criteria` grep gates verified: `check_and_increment` present, `f"{engagement_id}:{finding_id}"` key format present, zero occurrences of `backend.core` import, no CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW logic (only docstring mentions of what's excluded).

## TDD Gate Compliance

- `test(02-04): add failing DATA-02 budget-isolation test for VerificationLoop` — commit `c89cca0` (RED gate) ✓
- `feat(02-04): implement VerificationLoop scoping stub for DATA-02` — commit `d86aa07` (GREEN gate) ✓
- No REFACTOR commit needed — implementation matched the RESEARCH.md/PATTERNS.md target on first pass.

## Known Stubs

None beyond the plan's own intentional scope. `VerificationLoop` is explicitly a scoping-only stub (per D-08/D-09) — it has zero live callers this phase (same as `VerificationPolicy`), and v1.1 Phase 5 will extend it with classification logic and tool dispatch. This is documented in the module docstring, not a hidden gap.

## Threat Flags

None. This plan's changes stay entirely within the threat model already declared in `02-04-PLAN.md` (T-02-09, T-02-10) — no new network endpoints, auth paths, file access patterns, or schema changes were introduced.

## Self-Check: PASSED

- FOUND: backend/verification/verification_loop.py
- FOUND: tests/verification/__init__.py
- FOUND: tests/verification/test_verification_loop.py
- FOUND commit: c89cca0
- FOUND commit: d86aa07
