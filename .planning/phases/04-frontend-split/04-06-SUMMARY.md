---
phase: 04-frontend-split
plan: 06
subsystem: frontend
tags: [react, components, extraction, refactor]

# Dependency graph
requires: [04-01, 04-02]
provides:
  - "frontend/components/StatusBar.jsx — co-locates StatusBar + EngagementTimer, connection indicators from props"
  - "frontend/components/TerminalLine.jsx — single terminal output line renderer"
  - "frontend/components/TerminalInput.jsx — REST POST /terminal/exec + inline error banner"
  - "frontend/components/TerminalPanel.jsx — composes TerminalLine + TerminalInput, auto-scroll"
  - "frontend/components/FindingsPanel.jsx — findings list + report download (POST /report/*, blob download)"
  - "frontend/components/panels-batch2.smoke.test.jsx — import + shallow-render smoke tests for the batch"
affects: [04-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Verbatim extraction: module boundary changes, logic/JSX unchanged"
    - "Co-located sub-components: StatusBar+EngagementTimer, TerminalPanel+TerminalLine+TerminalInput (each its own file, composed via import)"

key-files:
  created:
    - frontend/components/StatusBar.jsx
    - frontend/components/TerminalLine.jsx
    - frontend/components/TerminalInput.jsx
    - frontend/components/TerminalPanel.jsx
    - frontend/components/FindingsPanel.jsx
    - frontend/components/panels-batch2.smoke.test.jsx
  modified: []

key-decisions:
  - "Kept StatusBar's existing prop names (health, wsEvents, wsChat, engagementActive, startTime) rather than renaming to chatConnected/eventsConnected/terminalConnected as the plan's <interfaces> note paraphrased — the plan's own <action> text says 'verbatim' and the acceptance criteria only requires 'renders three connection indicators from props'; App.jsx (untouched this plan) still calls StatusBar with the original prop names, and 04-07 owns wiring the redefined session-acked semantic for wsChat per D-08/UI-SPEC, not a prop rename"
  - "Polyfilled Element.prototype.scrollIntoView inside panels-batch2.smoke.test.jsx only (jsdom does not implement it) — TerminalPanel's auto-scroll effect is a verbatim extraction from App.jsx and calls scrollIntoView on mount; this is a test-environment gap, not a code defect, so the fix is scoped to the test file, not the component"
  - "Ran npm install in frontend/ (node_modules was empty in this worktree) solely to execute the plan's verification commands — no tracked file changed as a result (node_modules is gitignored, package-lock.json unchanged)"

patterns-established:
  - "Batch-N smoke test pattern (frontend/components/panels-batchN.smoke.test.jsx): render each extracted panel with minimal/empty props, assert it mounts without throwing and shows an expected root-level text/element"

requirements-completed: [UI-02]

# Metrics
duration: 22min
completed: 2026-09-04
---

# Phase 04 Plan 06: Extract StatusBar, Terminal Trio, and FindingsPanel Summary

**Extracted the three heaviest remaining panel groups from App.jsx into standalone files — StatusBar (co-located with EngagementTimer), the Terminal trio (TerminalLine/TerminalInput/TerminalPanel composing each other), and FindingsPanel (the only file-download flow in the codebase) — all verbatim, all REST/WS calls preserved unchanged, completing the panel-extraction half of UI-02.**

## Performance

- **Duration:** 22 min
- **Started:** 2026-09-04T17:44:00Z (approx)
- **Completed:** 2026-09-04T18:06:06Z
- **Tasks:** 2
- **Files modified:** 6 (all new files)

## Accomplishments

- `StatusBar.jsx` co-locates `StatusBar` (default export) and `EngagementTimer`, moved verbatim from `App.jsx` lines 188-263; renders BACKEND/EVENT STREAM/CHAT/KALI/TOKEN BUDGET indicators plus the engagement timer, all from props
- `TerminalLine.jsx`, `TerminalInput.jsx`, `TerminalPanel.jsx` extracted verbatim from `App.jsx` lines 483-673; `TerminalPanel` imports and composes `TerminalLine` and `TerminalInput` from their new files; `TerminalInput` preserves the `fetch('/terminal/exec', {method:'POST'})` call and its inline error-state handling unchanged
- `FindingsPanel.jsx` extracted verbatim from `App.jsx` lines 675-872, including the `triggerDownload`/`downloadReport` blob-download flow and both `/report/{format}` and `/report/{format}/{type}` POST calls; imports `SEVERITY_MAP`, `REPORT_FORMATS_UI`, `REPORT_FRAMEWORKS` from `frontend/lib/constants` (04-02) instead of redefining them
- `panels-batch2.smoke.test.jsx` renders all five batch-2 exports (StatusBar, TerminalPanel, TerminalInput, TerminalLine, FindingsPanel) with minimal/empty props and asserts each mounts without throwing
- `App.jsx` and `App.test.jsx` untouched — full suite (4 test files, 21 tests) passes unchanged, confirming zero regression

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract StatusBar (+EngagementTimer) and the Terminal trio (TerminalLine, TerminalInput, TerminalPanel)** - `d818fca` (feat)
2. **Task 2: Extract FindingsPanel (report download) + smoke tests for the batch** - `b44a734` (feat)

## Files Created/Modified

- `frontend/components/StatusBar.jsx` - New. Default-exports `StatusBar`, co-locates `EngagementTimer`. Moved verbatim from `App.jsx` lines 188-263; imports `Shield` from `lucide-react` and `fmtElapsed` from `../lib/format`
- `frontend/components/TerminalLine.jsx` - New. Default-exports `TerminalLine({ line })`, moved verbatim from `App.jsx` lines 483-536
- `frontend/components/TerminalInput.jsx` - New. Default-exports `TerminalInput({ agentActive })`, moved verbatim from `App.jsx` lines 538-608; imports `AlertTriangle` from `lucide-react`
- `frontend/components/TerminalPanel.jsx` - New. Default-exports `TerminalPanel({ lines, agentActive, wsConnected })`, moved verbatim from `App.jsx` lines 610-673; imports `TerminalLine` and `TerminalInput` from their new sibling files
- `frontend/components/FindingsPanel.jsx` - New. Default-exports `FindingsPanel({ findings })`, moved verbatim from `App.jsx` lines 675-872; imports `SEVERITY_MAP`/`REPORT_FORMATS_UI`/`REPORT_FRAMEWORKS` from `../lib/constants`
- `frontend/components/panels-batch2.smoke.test.jsx` - New. 5 smoke tests (one per component), plus a local `Element.prototype.scrollIntoView` polyfill scoped to this test file

## Decisions Made

- Kept `StatusBar`'s prop names as-is (`health`, `wsEvents`, `wsChat`, `engagementActive`, `startTime`) rather than the plan's `<interfaces>` note's paraphrased `chatConnected`/`eventsConnected`/`terminalConnected` — the task `<action>` explicitly says "verbatim," App.jsx (which still calls `StatusBar` today) is out of scope for this plan, and 04-07 is the plan that rewires the session-acked semantic per D-08
- Scoped the jsdom `scrollIntoView` polyfill to the smoke test file only, not the component — `TerminalPanel`'s auto-scroll effect is a verbatim extraction and works correctly in real browsers; jsdom simply doesn't implement the API
- Ran `npm install` in `frontend/` (empty `node_modules` in this fresh worktree) purely to execute the plan's `<verify>` and overall verification commands — no tracked file changed (`node_modules/` gitignored, `package-lock.json` unchanged)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking test-infra issue] jsdom missing `scrollIntoView` implementation**
- **Found during:** Task 2, running `panels-batch2.smoke.test.jsx`
- **Issue:** `TerminalPanel`'s auto-scroll `useEffect` (verbatim from `App.jsx`) calls `bottomRef.current?.scrollIntoView({ behavior: 'smooth' })` on mount; jsdom (the test environment) does not implement `Element.prototype.scrollIntoView`, causing a `TypeError` that failed the smoke render
- **Fix:** Added a no-op polyfill (`Element.prototype.scrollIntoView = () => {}`) inside `panels-batch2.smoke.test.jsx`'s `beforeAll`, scoped to that file only — component source was not touched
- **Files modified:** `frontend/components/panels-batch2.smoke.test.jsx`
- **Commit:** `b44a734`

## Issues Encountered

None beyond the jsdom polyfill above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `StatusBar.jsx`, `TerminalLine.jsx`, `TerminalInput.jsx`, `TerminalPanel.jsx`, `FindingsPanel.jsx` all exist as standalone importable files under `frontend/components/`
- 04-07 (App.jsx rewrite) can import all five directly and wrap each in an `ErrorBoundary` (already built in an earlier plan, per D-05)
- 04-07 owns wiring `StatusBar`'s `wsChat` prop to the redefined session-acked boolean from `ChatPane.tsx`/`SessionContext`
- No blockers identified for downstream plans

---
*Phase: 04-frontend-split*
*Completed: 2026-09-04*

## Self-Check: PASSED

- FOUND: frontend/components/StatusBar.jsx
- FOUND: frontend/components/TerminalLine.jsx
- FOUND: frontend/components/TerminalInput.jsx
- FOUND: frontend/components/TerminalPanel.jsx
- FOUND: frontend/components/FindingsPanel.jsx
- FOUND: frontend/components/panels-batch2.smoke.test.jsx
- FOUND commit: d818fca (Task 1)
- FOUND commit: b44a734 (Task 2)
