---
phase: 01-cleanup-configuration
plan: 02
subsystem: testing
tags: [pytest, python, dead-code, cleanup, test-suite]

# Dependency graph
requires:
  - phase: 01-cleanup-configuration
    provides: Research confirming 18 backend/tests files exclusively test dead-code modules (backend/core, backend/agents, backend/main)
provides:
  - 18 dead-code test files deleted from backend/tests/
  - pyproject.toml testpaths updated to point at canonical tests/ suite
  - pytest tests/ runs 35 tests cleanly with exit code 0
  - backend/tests/ orphaned with 9 preserved files for Plan 03 inspection
affects:
  - 01-cleanup-configuration plan 03 (will inspect 9 preserved files and remove backend/tests/ entirely)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Canonical test suite is tests/ (not backend/tests/) — pytest testpaths enforces this"
    - "backend/tests/ intentionally orphaned for one wave; Plan 03 will remove it"

key-files:
  created: []
  modified:
    - pyproject.toml — testpaths changed from ["backend/tests"] to ["tests"]

key-decisions:
  - "Delete all 18 dead-code test files even those with secondary live imports (verification_loop, tools.tool_spec) — the files test dead-code orchestration (OmX, OmO, old agents, PermissionPipeline) and have no value without the modules being deleted in Plan 03"
  - "Set testpaths to [\"tests\"] only (not both suites) since backend/tests/ files are orphaned and will be decided in Plan 03"

patterns-established:
  - "Plan 02 establishes the gate: pytest green on tests/ before Plan 03 deletes backend/core, backend/agents, backend/main"

requirements-completed: [CLEAN-01]

# Metrics
duration: 15min
completed: 2026-05-12
---

# Phase 1 Plan 02: Delete Dead-Code Tests and Repoint Pytest Summary

**Deleted 18 backend/tests files testing dead OmX/OmO/core/agents code, updated pyproject.toml testpaths to ["tests"], confirmed 35-test canonical suite exits green**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-05-12T08:00:00Z
- **Completed:** 2026-05-12T08:15:00Z
- **Tasks:** 3
- **Files modified:** 1 (pyproject.toml) + 18 deleted

## Accomplishments

- Deleted 18 `backend/tests/` files that exclusively test dead-code modules (`backend/core/`, `backend/agents/`, `backend/main`) — confirmed by RESEARCH.md table and per-file import analysis
- Updated `pyproject.toml` `testpaths` from `["backend/tests"]` to `["tests"]` so `pytest` runs only the canonical new-system suite
- Verified `pytest tests/ -v --tb=short` exits 0 with 35 tests passed, zero errors, zero `ModuleNotFoundError`
- `backend/tests/` now contains exactly 10 entries: `__init__.py` + 9 preserved test files for Plan 03 inspection

## Task Commits

Each task was committed atomically:

1. **Task 1-02-01: Delete 17+1 backend/tests dead-code test files** - `f4b9809` (chore)
2. **Task 1-02-02: Update pyproject.toml testpaths from backend/tests to tests** - `bd8ef4c` (chore)
3. **Task 1-02-03: Verify pytest tests/ green** - (no commit needed — verification only, no files changed)

**Plan metadata:** committed with SUMMARY.md + STATE.md + ROADMAP.md

## Files Created/Modified

- `pyproject.toml` — `testpaths` changed from `["backend/tests"]` to `["tests"]`
- **Deleted (18 files):**
  - `backend/tests/test_base_agent_resilience.py` — tested `backend.core.base_agent.BaseAgent` (old)
  - `backend/tests/test_event_bus.py` — tested `backend.core.event_bus` (old)
  - `backend/tests/test_exploit_agent_fallback.py` — tested `backend.agents.exploit_agent` (old)
  - `backend/tests/test_intel_agent_enrich.py` — tested `backend.agents.intel_agent` (old)
  - `backend/tests/test_llm_json_hardening.py` — tested `backend.agents.scan_agent` (old)
  - `backend/tests/test_omx_enrichment.py` — tested `backend.core.omx.OmX` (old)
  - `backend/tests/test_omx_two_phase_exploit.py` — tested `backend.core.omx.OmX` (old)
  - `backend/tests/test_pentest_e2e.py` — tested OmX+OmO+old agents E2E (old)
  - `backend/tests/test_permission_pipeline.py` — tested `backend.core.permission.PermissionPipeline` (old)
  - `backend/tests/test_recon_agent_loop.py` — tested `backend.agents.recon_agent` (old)
  - `backend/tests/test_report_formats.py` — tested `backend.main._resolve_findings` (old)
  - `backend/tests/test_safety_regression.py` — tested `backend.core.scope_enforcer.ScopeEnforcer` (old)
  - `backend/tests/test_scope_discovery_target_type.py` — tested `backend.agents.scope_discovery_agent` (old)
  - `backend/tests/test_session_merge.py` — tested `backend.core.session.Session` (old)
  - `backend/tests/test_terminal_broadcaster.py` — tested `backend.core.terminal_broadcaster` + `backend.main` (old)
  - `backend/tests/test_tool_fallback_resolver.py` — tested `backend.core.tool_fallback.ToolFallbackResolver` (old)
  - `backend/tests/test_verification_loop_classify.py` — tested `backend.core.models.FindingClassification` (old)
  - `backend/tests/test_verification_policy.py` — tested `backend.core.credential_vault` + `backend.core.models` (old)

## Decisions Made

- **Delete all 18 even with secondary live imports:** Several files (test_pentest_e2e.py, test_permission_pipeline.py, test_safety_regression.py, test_verification_loop_classify.py, test_verification_policy.py) also import from live modules (`backend.verification`, `backend.tools.tool_spec`, `backend.intelligence`). Decision: delete anyway. These files test dead orchestration code (OmX, OmO, PermissionPipeline, old core agents) — the live imports are secondary dependencies, not the primary purpose. RESEARCH.md explicitly listed all 18 as "tests that clearly test dead code."
- **testpaths = ["tests"] only (not both):** The 9 preserved backend/tests files are intentionally excluded from default pytest runs — they are orphaned for Plan 03 inspection, not meant to run by default while they still import from (potentially still-present) old modules.

## Deviations from Plan

None — plan executed exactly as written.

The per-file import analysis revealed some files had secondary live imports (mixed dead+live), which initially looked like a deviation trigger. However, RESEARCH.md had already anticipated this and explicitly included all 18 files in the "delete" list with clear reasoning. The live imports (e.g., `backend.verification.verification_loop`) were secondary dependencies used by dead-code test fixtures, not the primary subject being tested. Proceeded with deletion as specified.

## Issues Encountered

None. All 35 tests in `tests/` passed on first run after the testpaths update.

## Known Stubs

None — this plan performs deletion and configuration only. No stub values were introduced.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 03 can now safely delete `backend/core/`, `backend/agents/`, `backend/main.py` — no test files importing from them remain in the pytest-collected `tests/` suite
- Plan 03 must inspect the 9 preserved `backend/tests/` files to decide migrate-or-delete, then remove `backend/tests/` entirely
- The canonical test suite (`tests/`) runs 35 tests green — regression baseline is established

---
*Phase: 01-cleanup-configuration*
*Completed: 2026-05-12*
