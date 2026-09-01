---
phase: 03-orchestration-upgrade
plan: 07
subsystem: agent-orchestration
tags: [dedup, code-hygiene, instruction-parser, engine-router]
requires: []
provides:
  - "reconciled backend/agent/instruction_parser.py (single canonical EngineRouter, EngagementSession-typed parse())"
affects:
  - backend/agent/instruction_parser.py
tech-stack:
  added: []
  patterns:
    - "Delegate to canonical EngineRouter().dispatch(intent, target) instead of reading a stale session field"
key-files:
  created:
    - tests/agent/test_instruction_parser.py
    - .planning/phases/03-orchestration-upgrade/deferred-items.md
  modified:
    - backend/agent/instruction_parser.py
decisions:
  - "Reconciled InstructionParser stays uncalled in production per D-02a — OmX's LLM-driven DAG generation supersedes its regex intent/target detection; no new caller was added"
metrics:
  duration: 35min
  completed: 2026-09-01
---

# Phase 3 Plan 07: Reconcile instruction_parser.py (dedupe EngineRouter, retype to EngagementSession) Summary

Deleted the byte-identical duplicate `EngineRouter` class from `instruction_parser.py` and retyped `InstructionParser.parse()` from the dead `SessionState` to the live `EngagementSession`, deriving the returned `mode` via `EngineRouter().dispatch(intent, target)` instead of reading a nonexistent `session.mode` field.

## What Was Built

`backend/agent/instruction_parser.py` previously defined its own copy of `EngineRouter` (a near-duplicate of `backend/agent/engine_router.py`'s canonical class) and typed `InstructionParser.parse()`'s `session` parameter as `SessionState` — a class from `backend/agent/conversation.py` that has no `.mode` attribute in the current `EngagementSession` model. Calling `parse()` against a real `EngagementSession` would raise `AttributeError: 'EngagementSession' object has no attribute 'mode'`.

This plan:
- Removed the local duplicate `EngineRouter` class entirely and imported the canonical one from `backend.agent.engine_router`.
- Changed `parse()`'s signature to accept `session: EngagementSession` (imported from `backend.session.engagement_session`).
- Replaced `"mode": mode or session.mode` with `"mode": mode or EngineRouter().dispatch(intent, target)` — the one genuine design decision in this plan (not a mechanical rename), since `EngagementSession` carries no per-session mode field and the per-message engine dispatch is the correct analog.
- Removed the now-unused `from backend.agent.conversation import SessionState` import.
- Left all five regex-based helper methods (`_detect_intent`, `_extract_target`, `_extract_constraints`, `_detect_phase`, `_calculate_confidence`) byte-identical.
- Added `tests/agent/test_instruction_parser.py` (4 tests, plain pytest, mirrors `test_llm_router.py` style) covering: no-AttributeError parse against a real `EngagementSession`, explicit `mode=` passthrough, `mode=None` derivation via `EngineRouter().dispatch()`, and absence of a locally-defined `EngineRouter` in the module.

Per **D-02a** (recorded in `03-CONTEXT.md`): this reconciliation is deliberate code hygiene, not a re-wiring. `InstructionParser.parse()` has zero live callers today (confirmed via full-repo grep — `orchestrator.py` only does `self.parser = InstructionParser()`, never calls `.parse()`) and this plan does **not** add one. OmX's LLM-driven DAG generation (D-06) supersedes `InstructionParser`'s regex intent/target detection and `EngineRouter`'s regex engine-selection — Claude decomposes the operator directive directly into `Directive.engine`/`Directive.agent`/`Directive.tools`. The class intentionally stays uncalled in production.

## Verification

- `pytest tests/agent/test_instruction_parser.py -x --tb=short` — 4 passed
- `python -c "import ast,inspect; import backend.agent.instruction_parser as m; assert not hasattr(m,'EngineRouter') or m.EngineRouter.__module__=='backend.agent.engine_router'; print('ok')"` — `ok`
- `python -c "import backend.agent.instruction_parser, backend.agent.orchestrator"` — imports clean
- `grep -n "session.mode\|SessionState" backend/agent/instruction_parser.py` — no matches
- Full test suite (`pytest`, 180 collected): 158 passed, 6 skipped, 15 xfailed, 1 failed (pre-existing, unrelated — see Deferred Issues below)

Test environment note: this worktree's host Python is 3.14 (incompatible with the project's pinned `pydantic-core`/`tiktoken` build requirements — Python 3.12 is required per `backend/Dockerfile`). Tests were run inside an ad-hoc `python:3.12-slim` Docker container with `backend/requirements.txt` installed, mounting the worktree at `/app`. No project files were changed to accommodate this; it is purely a local test-execution workaround.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written. The mode-derivation logic (`EngineRouter().dispatch(intent, target)`) was the plan's own explicitly-called-out design decision, not an unplanned deviation.

## Requirements Note

This plan's frontmatter declares `requirements: [ORCH-03]`, but ORCH-03 ("`OmX` planner implements template-first planning with an 8-directive phase DAG") is shared across four plans in this phase (03-06, 03-07, 03-08, 03-09). Plan 03-07 only performs the `instruction_parser.py` dedupe/retype prerequisite — it does not implement the OmX DAG itself. Running `gsd-sdk query requirements.mark-complete ORCH-03` here would flip the requirement to "Complete" in `.planning/REQUIREMENTS.md` based on this single contributing plan, which would misrepresent the true state (the OmX DAG work in 03-06/03-08/03-09 may not yet be merged). That REQUIREMENTS.md change was reverted (`git checkout -- .planning/REQUIREMENTS.md`) and ORCH-03 is intentionally left unmarked here — it should be marked complete only once all four contributing plans have landed, ideally by the orchestrator after aggregating the full wave/phase.

## Deferred Issues (out of scope)

- `tests/api/test_auth.py::test_chat_without_token_returns_401` fails (`assert 403 == 401`) on a full-suite run. This is unrelated to `instruction_parser.py`/`engine_router.py` — almost certainly a FastAPI/Starlette `HTTPBearer` version behavior change (missing-credentials now returns 403). Out of scope per executor scope-boundary rule; logged in `.planning/phases/03-orchestration-upgrade/deferred-items.md`, not fixed.

## Known Stubs

None introduced by this plan.

## Threat Flags

None — the only threat register entry for this plan (T-03-07, duplicate `EngineRouter` drift) was fully mitigated by deleting the duplicate class, as planned. No new network endpoints, auth paths, file-access patterns, or schema changes were introduced.

## Self-Check: PASSED

- FOUND: backend/agent/instruction_parser.py (modified, imports EngineRouter from backend.agent.engine_router, no local EngineRouter class)
- FOUND: tests/agent/test_instruction_parser.py (4 tests, all passing)
- FOUND: .planning/phases/03-orchestration-upgrade/deferred-items.md
- FOUND commit 32714bd (test(03-07): add failing test for instruction_parser EngagementSession retype)
- FOUND commit 95dca2b (feat(03-07): dedupe EngineRouter and retype InstructionParser.parse to EngagementSession)
- FOUND commit 8f3d6f3 (docs(03-07): log pre-existing out-of-scope test_auth 401/403 failure)
