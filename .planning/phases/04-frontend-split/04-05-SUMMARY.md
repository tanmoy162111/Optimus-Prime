---
phase: 04-frontend-split
plan: 05
subsystem: frontend
tags: [react, componentization, refactor, extraction]

# Dependency graph
requires: [04-01, 04-02]
provides:
  - "frontend/components/ScopePanel.jsx — scope config form (REST POST /scope via onSetScope)"
  - "frontend/components/DirectivesPanel.jsx — directive trigger chips (onSendDirective)"
  - "frontend/components/PlanPanel.jsx — engagement plan renderer with empty state"
  - "frontend/components/AgentTracker.jsx — agent status tracker"
  - "frontend/components/HealthPanel.jsx — health status panel (onRefresh GET /health)"
  - "frontend/components/panels-batch1.smoke.test.jsx — import + shallow-render smoke tests for the five panels"
affects: [04-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Verbatim extraction: module boundary changes (imports/exports/props), JSX/logic unchanged"

key-files:
  created:
    - frontend/components/ScopePanel.jsx
    - frontend/components/DirectivesPanel.jsx
    - frontend/components/PlanPanel.jsx
    - frontend/components/AgentTracker.jsx
    - frontend/components/HealthPanel.jsx
    - frontend/components/panels-batch1.smoke.test.jsx
  modified: []

key-decisions:
  - "DirectivesPanel's true App.jsx signature is DirectivesPanel({ directives, onSendDirective }) — the plan's <interfaces> section listed only onSendDirective, but the source (App.jsx line 377, call site line 1459) requires directives for Object.keys/Object.entries. Kept the real signature to satisfy the must_haves.truths verbatim-preservation requirement; the smoke test passes directives={{}} accordingly."
  - "HealthPanel's outer wrapper is exactly className=\"panel\" (no flex flex-col h-full) in the source App.jsx — preserved as-is rather than normalizing to the more common panel shape used by the other four, since the plan requires verbatim preservation, not standardization."
  - "Ran npm install in frontend/ to obtain a working node_modules for running the vitest verification commands (mirrors 04-02's precedent) — node_modules is gitignored, no tracked file changed by this."

patterns-established: []

requirements-completed: []

# Metrics
duration: 20min
completed: 2026-09-05
---

# Phase 04 Plan 05: Extract ScopePanel, DirectivesPanel, PlanPanel, AgentTracker, HealthPanel Summary

**Extracted five verbatim inline sub-components (ScopePanel, DirectivesPanel, PlanPanel, AgentTracker, HealthPanel) out of App.jsx into standalone frontend/components/*.jsx files with zero behavior/styling change, plus a shared smoke test proving each panel is independently importable — advancing UI-02 without touching App.jsx.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 2
- **Files created:** 6 (all new files)

## Accomplishments

- `frontend/components/ScopePanel.jsx` — verbatim relocation of `App.jsx` lines 265-375: local form state (`targets`, `excluded`, `ports`, `stealth`, `frameworks`, `notes`, `saving`), `handleSave` building the same payload shape, and the unchanged `onSetScope` callback wired to `App.jsx`'s `/scope` POST — no fetch stubbed, removed, or altered
- `frontend/components/DirectivesPanel.jsx` — verbatim relocation of `App.jsx` lines 377-420: local `icons` map and directive chip rendering, `directives`/`onSendDirective` props preserved exactly as the real App.jsx source declares them
- `frontend/components/HealthPanel.jsx` — verbatim relocation of `App.jsx` lines 1181-1221, including its exact `className="panel"` (not the 4-arg flex variant) outer wrapper
- `frontend/components/PlanPanel.jsx` — verbatim relocation of `App.jsx` lines 929-1013, including the early-return empty state (lines 930-944)
- `frontend/components/AgentTracker.jsx` — verbatim relocation of `App.jsx` lines 874-927
- `frontend/components/panels-batch1.smoke.test.jsx` — five tests (one per panel), each rendering with minimal/empty props and asserting a `.panel` element mounts without throwing
- `App.jsx` untouched throughout both tasks (verified via `git diff --stat` against both new commits — zero changes to `frontend/src/App.jsx`)
- Full existing frontend test suite still green: `npx vitest run` — 4 test files, 21 tests, all passing (includes the pre-existing `ErrorBoundary.test.jsx` and the new smoke test file)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract ScopePanel, DirectivesPanel, and HealthPanel (verbatim)** - `bf79236` (feat)
2. **Task 2: Extract PlanPanel and AgentTracker (verbatim) + smoke tests for the batch** - `d3585ec` (feat)

## Files Created/Modified

- `frontend/components/ScopePanel.jsx` - New. Default-export `ScopePanel({ scope, onSetScope })`, moved verbatim from `App.jsx` lines 265-375, `useState` import added
- `frontend/components/DirectivesPanel.jsx` - New. Default-export `DirectivesPanel({ directives, onSendDirective })`, moved verbatim from `App.jsx` lines 377-420
- `frontend/components/HealthPanel.jsx` - New. Default-export `HealthPanel({ health, onRefresh })`, moved verbatim from `App.jsx` lines 1181-1221
- `frontend/components/PlanPanel.jsx` - New. Default-export `PlanPanel({ plan })`, moved verbatim from `App.jsx` lines 929-1013 (includes empty-state early return)
- `frontend/components/AgentTracker.jsx` - New. Default-export `AgentTracker({ agents })`, moved verbatim from `App.jsx` lines 874-927
- `frontend/components/panels-batch1.smoke.test.jsx` - New. Five `@testing-library/react` render + `.panel` presence assertions, one per batch-1 panel

## Decisions Made

- Kept `DirectivesPanel`'s real prop signature (`{ directives, onSendDirective }`) rather than the plan interface's abbreviated `{ onSendDirective }` — the actual App.jsx source (and its only call site) requires `directives` for `Object.keys(directives).length` and `Object.entries(directives).map(...)`; using the abbreviated signature would have produced a component that throws on render, violating the plan's own verbatim-preservation truth. Smoke test passes `directives={{}}` to match.
- Preserved `HealthPanel`'s exact outer `className="panel"` (without `flex flex-col h-full`) rather than normalizing it to match the other four panels' fuller class list — plan explicitly requires verbatim extraction, not stylistic harmonization.
- Ran `npm install` in `frontend/` once (dependencies were not present in this worktree) solely to execute the plan's `<verify>` and overall `<verification>` steps — `node_modules/` is gitignored, no tracked file was changed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Plan's `<interfaces>` prop signature for DirectivesPanel omitted the required `directives` prop**
- **Found during:** Task 1 (reading App.jsx lines 377-420 and its call site at line 1459 before extraction)
- **Issue:** The plan's `<interfaces>` block documents `DirectivesPanel({ onSendDirective })`, but the true App.jsx source declares `DirectivesPanel({ directives, onSendDirective })` and uses `directives` for both the "N available" count and the rendered chip list. Extracting with the abbreviated signature would produce a component that throws `Cannot convert undefined or null to object` on render whenever `directives` isn't explicitly passed — contradicting the plan's own must_haves.truths ("preserves its existing props/callbacks ... verbatim").
- **Fix:** Extracted with the real, verified signature (`{ directives, onSendDirective }`); Task 2's smoke test passes `directives={{}}` to exercise it safely.
- **Files modified:** `frontend/components/DirectivesPanel.jsx`, `frontend/components/panels-batch1.smoke.test.jsx`
- **Commit:** `bf79236` (component), `d3585ec` (smoke test)

## Issues Encountered

None beyond the DirectivesPanel signature correction above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All five batch-1 panels (`ScopePanel`, `DirectivesPanel`, `PlanPanel`, `AgentTracker`, `HealthPanel`) now exist as standalone, independently importable, smoke-tested files under `frontend/components/`
- 04-06 will extract the remaining panels (`StatusBar`, `TerminalPanel`/`TerminalLine`/`TerminalInput`, `FindingsPanel`, `ChatMessage`) — no overlap or shared file conflicts with this plan's outputs
- 04-07 (App.jsx rewrite) can now import all five of these panels directly and wrap each in `ErrorBoundary` per D-05 — no further changes needed to the panel files themselves
- No blockers identified for downstream plans

---
*Phase: 04-frontend-split*
*Completed: 2026-09-05*
