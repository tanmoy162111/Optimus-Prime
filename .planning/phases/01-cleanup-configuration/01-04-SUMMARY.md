---
phase: 01-cleanup-configuration
plan: 04
subsystem: intelligence
tags: [python, imports, dead-code, custom-tool-generator, llm-router]

# Dependency graph
requires:
  - phase: 01-cleanup-configuration
    provides: backend.core / backend.agents / backend.main deleted; new system canonical
provides:
  - "custom_tool_generator.py with zero deferred dead imports at any indentation level"
  - "generate_tool() LLM branch uses plain dict messages matching live LLMRouter.complete() signature"
  - "_register_tool() raises NotImplementedError immediately — no deleted module imports execute at runtime"
  - "Full Phase 01 cleanup-configuration goal of zero broken imports is now complete and fully verified"
affects: [02-security-hardening, tool-registry-rebuild]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Stub-with-NotImplementedError pattern: dead import paths replaced by immediate raise rather than deferred import that fails at runtime"
    - "LLMRouter message format: plain dict {role, content} — not LLMMessage objects (deleted with backend.core)"

key-files:
  created: []
  modified:
    - backend/intelligence/custom_tool_generator.py

key-decisions:
  - "Use NotImplementedError stub for _register_tool() — honest stub that raises immediately vs. deferring to runtime ModuleNotFoundError"
  - "Remove max_tokens and temperature kwargs from self._llm.complete() call — live LLMRouter.complete() does not accept them; passing would raise TypeError"
  - "Rename system_prompt= to system= to match live LLMRouter.complete() signature"

patterns-established:
  - "When dead import path is unavoidable (method body depends on deleted module), use NotImplementedError with a clear message naming the deleted modules and which phase will resolve it"

requirements-completed: []

# Metrics
duration: 7min
completed: 2026-05-12
---

# Phase 01 Plan 04: Custom Tool Generator Dead Import Fix Summary

**Replaced two deferred `backend.core` / `backend.tools.tool_spec` dead imports in `custom_tool_generator.py` with working code and a NotImplementedError stub, closing the final Phase 01 gap for zero broken imports**

## Performance

- **Duration:** 7 min
- **Started:** 2026-05-12T05:05:00Z
- **Completed:** 2026-05-12T05:12:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Eliminated `from backend.core.llm_router import LLMMessage` deferred import (line 294) — replaced with plain dict message matching live `LLMRouter.complete()` signature
- Eliminated `from backend.tools.tool_spec import ToolSpec` and `from backend.core.models import ...` deferred imports (lines 488-489) — replaced with `raise NotImplementedError` stub
- Phase 01 cleanup-configuration goal of "zero broken imports" is now fully verified: `grep -rn "backend\.core\|backend\.agents\|backend\.main" backend/ --include="*.py"` returns only docstring/string-literal references, zero actual import statements
- Full test suite remains green: 144 passed, 2 skipped, 15 xfailed, exit code 0

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix deferred dead imports in custom_tool_generator.py** - `592a4ac` (fix)

**Plan metadata:** (pending final docs commit)

## Files Created/Modified

- `backend/intelligence/custom_tool_generator.py` - Removed two dead deferred import blocks; generate_tool() LLM branch now uses plain dict; _register_tool() raises NotImplementedError immediately

## Decisions Made

- Used `raise NotImplementedError` for `_register_tool()` rather than leaving dead imports — the deferred `from backend.tools.tool_spec import ToolSpec` would raise `ModuleNotFoundError` at runtime when the approve path executes; an immediate `NotImplementedError` with a clear message is more honest and easier to diagnose
- Removed `max_tokens=2048, temperature=0.3` kwargs from `self._llm.complete()` call — live `LLMRouter.complete()` accepts only `messages`, `mode`, and `system`; extra kwargs would raise `TypeError` at runtime
- Renamed `system_prompt=` to `system=` to match the live `LLMRouter.complete()` parameter name

## Deviations from Plan

None - plan executed exactly as written. Both BEFORE/AFTER replacement blocks applied verbatim.

## Issues Encountered

None. The 4 xfail tests that call the approve path continue to xfail — they now catch `NotImplementedError` instead of `ModuleNotFoundError`, but xfail catches both. Test outcomes unchanged.

## Known Stubs

- `backend/intelligence/custom_tool_generator.py` — `_register_tool()` raises `NotImplementedError`. This is an intentional stub documented in the plan. The full implementation requires `ToolSpec` and model types from `backend.tools.tool_spec` / `backend.core.models`, which were deleted in Phase 01. Phase 2 will rebuild the tool registry subsystem. 4 tests remain xfail tracking this.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 01 cleanup-configuration is now fully complete: all dead code deleted, all broken imports resolved (top-level and deferred), test suite green at 144 passed
- Phase 2 (Security Hardening) can begin: Docker sandbox, WAL mode, VerificationLoop scoping, per-engagement Kali workdirs
- Phase 2 must also implement `_register_tool()` when rebuilding the tool registry subsystem (tracked via 4 xfail tests)

---
*Phase: 01-cleanup-configuration*
*Completed: 2026-05-12*
