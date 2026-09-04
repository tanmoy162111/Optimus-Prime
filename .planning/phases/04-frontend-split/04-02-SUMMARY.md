---
phase: 04-frontend-split
plan: 02
subsystem: frontend
tags: [react, hooks, websocket, refactor, extraction]

# Dependency graph
requires: [04-01]
provides:
  - "frontend/hooks/useWebSocket.js — shared WebSocket hook (reconnect/backoff/heartbeat/mountedRef StrictMode guard)"
  - "frontend/lib/constants.js — SEVERITY_MAP, EVENT_ICONS, REPORT_FORMATS_UI, REPORT_FRAMEWORKS"
  - "frontend/lib/format.js — fmtTime, fmtElapsed, renderPayload"
affects: [04-03, 04-04, 04-05, 04-06, 04-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Verbatim extraction: module boundary changes, logic/JSX unchanged"

key-files:
  created:
    - frontend/hooks/useWebSocket.js
    - frontend/lib/constants.js
    - frontend/lib/format.js
  modified: []

key-decisions:
  - "constants.js imports only the 17 lucide-react icons actually referenced by EVENT_ICONS (Zap, Layers, CheckCircle, ChevronRight, Cpu, Activity, XCircle, AlertTriangle, Eye, Lock, Terminal, WifiOff, Clock, RefreshCw, Shield, Globe, Target) — a subset of App.jsx's full icon import list, not the whole list"
  - "renderPayload contains no JSX (pure string-building), so format.js stays a plain .js file per the plan's conditional instruction — no .jsx rename needed"
  - "Did not touch App.jsx or App.test.jsx in this plan — the swap to imports happens in 04-07 per plan scope"

patterns-established:
  - "Shared hooks live in frontend/hooks/, shared utilities/constants live in frontend/lib/ — both as plain named-export modules"

requirements-completed: [UI-01, UI-02]

# Metrics
duration: 12min
completed: 2026-09-04
---

# Phase 04 Plan 02: Extract Shared WebSocket Hook and Utility Modules Summary

**Extracted the duplicated useWebSocket hook and module-level constants/formatters out of App.jsx into three standalone importable modules (frontend/hooks/useWebSocket.js, frontend/lib/constants.js, frontend/lib/format.js) with zero behavior change, unblocking downstream ChatPane and panel-extraction plans.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-09-04T17:45:00Z (approx, wall-clock during execution)
- **Completed:** 2026-09-04T17:57:29Z
- **Tasks:** 2
- **Files modified:** 3 (all new files)

## Accomplishments

- `frontend/hooks/useWebSocket.js` created as a verbatim relocation of `App.jsx` lines 66-184: preserves the `/health` health-check gate, `getBackoffDelay` exponential backoff, `startHeartbeat`/`stopHeartbeat`, the `mountedRef` StrictMode double-invoke guard, the `visibilitychange` reconnect-on-wake listener, and `lastSeq` sequence tracking exactly
- `frontend/lib/constants.js` created with named exports `SEVERITY_MAP`, `EVENT_ICONS`, `REPORT_FORMATS_UI`, `REPORT_FRAMEWORKS`, importing only the 17 lucide-react icons actually used by `EVENT_ICONS`
- `frontend/lib/format.js` created with named exports `fmtTime`, `fmtElapsed`, `renderPayload`
- `App.jsx` and `App.test.jsx` untouched, as required — existing `npx vitest run` suite (8 tests, 1 file) still passes unchanged, confirming zero regression

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract useWebSocket hook to frontend/hooks/useWebSocket.js (verbatim relocation)** - `88d96b9` (feat)
2. **Task 2: Extract shared constants and formatters to frontend/lib/** - `9a42b1f` (feat)

## Files Created/Modified

- `frontend/hooks/useWebSocket.js` - New. Named export `useWebSocket(url, onMessage, enabled = true)`, moved verbatim from `App.jsx` lines 67-183, with `import { useState, useEffect, useRef, useCallback } from 'react'` added at the top
- `frontend/lib/constants.js` - New. `SEVERITY_MAP`, `EVENT_ICONS` (with scoped lucide-react icon import), `REPORT_FORMATS_UI`, `REPORT_FRAMEWORKS`, moved verbatim from `App.jsx` lines 15-52
- `frontend/lib/format.js` - New. `fmtTime`, `fmtElapsed`, `renderPayload`, moved verbatim from `App.jsx` lines 54-63 and 459-479

## Decisions Made

- Scoped the `lucide-react` import in `constants.js` to only the 17 icons referenced across all `EVENT_ICONS` entries (cross-checked against every entry's `icon:` value), rather than copying App.jsx's full 23-icon import list — per the task's explicit instruction ("import only the icons actually used in these constants, not the whole list")
- Verified `renderPayload`'s body contains no JSX (it only builds and joins strings/template literals), so `format.js` was kept as a plain `.js` file rather than renamed to `.jsx`
- Ran `npm install` in `frontend/` (dependencies were not yet present in this worktree) solely to execute the plan's overall verification step (`npx vitest run`) — this did not modify any tracked file; `node_modules/` is already gitignored per 04-01

## Deviations from Plan

None — plan executed exactly as written. Both tasks' automated `<verify>` blocks passed on first attempt, and the plan-level `<verification>` step (`npx vitest run`) passed with all 8 existing tests green, confirming `App.jsx`/`App.test.jsx` were unaffected.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Three importable shared modules now exist: `frontend/hooks/useWebSocket.js`, `frontend/lib/constants.js`, `frontend/lib/format.js`
- 04-04 (`ChatPane.tsx`) can import `useWebSocket` directly
- 04-05/04-06 (data-rendering panels) can import from `constants.js`/`format.js` directly
- 04-07 (App.jsx rewrite) will swap App.jsx's inline copies for imports from these three modules and delete the inline `useWebSocket` copy in `App.test.jsx`
- No blockers identified for downstream plans

---
*Phase: 04-frontend-split*
*Completed: 2026-09-04*

## Self-Check: PASSED

- FOUND: frontend/hooks/useWebSocket.js
- FOUND: frontend/lib/constants.js
- FOUND: frontend/lib/format.js
- FOUND: .planning/phases/04-frontend-split/04-02-SUMMARY.md
- FOUND commit: 88d96b9 (Task 1)
- FOUND commit: 9a42b1f (Task 2)
