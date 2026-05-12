---
phase: 01-cleanup-configuration
plan: 01
subsystem: api
tags: [anthropic, claude, pydantic-settings, config, llm-router, pytest]

# Dependency graph
requires: []
provides:
  - Correct claude_model default ("claude-sonnet-4-6") in backend/config.py
  - Regression test asserting model identifier value
  - Regression test asserting SDK call kwargs include the configured model
affects: [02-security-hardening, 03-orchestration-upgrade]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Config-driven model selection: LLMRouter reads config.settings.claude_model at call time, so config.py is the single source of truth"

key-files:
  created: []
  modified:
    - backend/config.py
    - tests/agent/test_llm_router.py

key-decisions:
  - "Fixed claude_model from claude-opus-4-7 to claude-sonnet-4-6; the model ID was causing every Claude API call to 404 and silently fall back to Ollama"

patterns-established:
  - "Regression test for model identifier: test_claude_model_is_sonnet_4_6 asserts config.settings.claude_model at test time so future mis-edits are caught before deployment"

requirements-completed: [CLEAN-02]

# Metrics
duration: 5min
completed: 2026-05-12
---

# Phase 1 Plan 01: Fix Claude model identifier in backend config Summary

**Fixed silent Claude API 404 by correcting claude_model from non-existent "claude-opus-4-7" to "claude-sonnet-4-6" in backend/config.py, with two regression tests pinning the model string and SDK call kwargs**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-05-12T04:12:00Z
- **Completed:** 2026-05-12T04:12:26Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Corrected the invalid model string in `backend/config.py` — every Claude API call now uses "claude-sonnet-4-6" instead of the non-existent "claude-opus-4-7"
- Added `test_claude_model_is_sonnet_4_6`: a sync regression test that asserts `config.settings.claude_model == "claude-sonnet-4-6"` — any future mis-edit fails CI immediately
- Added `test_complete_passes_claude_sonnet_4_6_model_to_sdk`: an async test that patches the Anthropic SDK and verifies the model string flows end-to-end into the API call kwargs

## Task Commits

Each task was committed atomically:

1. **Task 1-01-01: Update claude_model default in backend/config.py** - `54ed4a3` (fix)
2. **Task 1-01-02: Add regression test asserting model identifier value and SDK call kwargs** - `ac8dd7c` (test)

## Files Created/Modified

- `backend/config.py` - Changed `claude_model` default from `"claude-opus-4-7"` to `"claude-sonnet-4-6"` (line 8, single string substitution)
- `tests/agent/test_llm_router.py` - Added `from backend import config` import and two new tests (`test_claude_model_is_sonnet_4_6`, `test_complete_passes_claude_sonnet_4_6_model_to_sdk`); original two tests untouched

## Decisions Made

- No architectural decisions required — single-line fix as planned
- Model string `"claude-sonnet-4-6"` confirmed as the current working model, corroborated by `backend/main.py` line 229 fallback default and the current executor model

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. pytest emitted Python 3.14 deprecation warnings about `asyncio.iscoroutinefunction` and `asyncio.get_event_loop_policy` being deprecated in 3.16, but these are in the pytest-asyncio plugin internals and are out of scope for this plan. Logged to deferred items.

## User Setup Required

None - no external service configuration required. The fix takes effect automatically; Claude API calls will use the corrected model ID on next backend restart.

## Next Phase Readiness

- CLEAN-02 complete: Claude API calls will now route to the correct model instead of 404-ing to Ollama fallback
- CLEAN-01 (delete old backend system) is the next plan in this phase and does not depend on this one
- No blockers

---
*Phase: 01-cleanup-configuration*
*Completed: 2026-05-12*
