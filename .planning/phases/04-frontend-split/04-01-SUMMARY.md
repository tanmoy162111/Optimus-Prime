---
phase: 04-frontend-split
plan: 01
subsystem: infra
tags: [npm, vite, vitest, next-js-removal, toolchain]

# Dependency graph
requires: []
provides:
  - Working frontend build/test toolchain (npm ci succeeds, npm run test invokes vitest)
  - Corrected frontend/package.json aligned with package-lock.json's real Vite/Vitest dependency tree
  - Dead Next.js page (frontend/pages/index.tsx) and dead /chat proxy entry removed
affects: [04-02, 04-03, 04-04, 04-05, 04-06, 04-07]

# Tech tracking
tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified:
    - frontend/package.json
    - frontend/package-lock.json
    - frontend/vite.config.js
    - .gitignore

key-decisions:
  - "Rewrote package.json to exactly match package-lock.json's real Vite/Vitest/Testing-Library toolchain (optimus-prime-ui 2.0.0), removing the dead Next.js/Socket.IO/Zustand manifest"
  - "Regenerated package-lock.json via npm install (not npm ci) per plan instruction, since package.json changed and the lockfile needed to catch up"
  - "Deleted frontend/pages/index.tsx and the now-empty pages/ directory (D-10) — dead Next.js page referencing nonexistent LivePanel"
  - "Removed dead /chat proxy entry from vite.config.js; /ws/chat already resolves through the existing /ws proxy prefix (ws: true)"
  - "Added node_modules/ and frontend/dist/ to .gitignore (Rule 2) — npm install left node_modules/ untracked with no prior ignore rule"
  - "Logged npm audit's 8 transitive dev-toolchain vulnerabilities to deferred-items.md instead of fixing — all are in pinned versions RESEARCH.md verified as mutually compatible (vitest 5/vite 8 produce a real ERESOLVE conflict); bumping majors is out of this plan's scope"

patterns-established: []

requirements-completed: [UI-01, UI-02, UI-03]

# Metrics
duration: 16min
completed: 2026-09-04
---

# Phase 04 Plan 01: Frontend Toolchain Fix Summary

**Rewrote frontend/package.json to the real Vite/Vitest toolchain, regenerated package-lock.json, and deleted the dead Next.js remnants (pages/index.tsx, /chat proxy entry) so npm ci and npm run test work correctly.**

## Performance

- **Duration:** 16 min (across two execution windows separated by a blocking-human package-legitimacy checkpoint)
- **Started:** 2026-09-04T23:38:00+06:00
- **Completed:** 2026-09-04T23:54:00+06:00
- **Tasks:** 2 (plus 1 checkpoint)
- **Files modified:** 5 (package.json, package-lock.json, vite.config.js, .gitignore, deferred-items.md; 1 deleted: pages/index.tsx)

## Accomplishments
- `frontend/package.json` now declares `optimus-prime-ui` 2.0.0 with the real Vite/Vitest/Testing-Library/Tailwind toolchain, matching what the live code (`App.jsx`, `App.test.jsx`, `vite.config.js`) already uses
- `frontend/package-lock.json` regenerated and now in sync — `npm ci` exits 0 (previously EUSAGE)
- `npx vitest run` executes and passes (8 tests, 1 test file) — no more silent lockfile drift to the wrong (Next.js) dependency set
- Dead `frontend/pages/index.tsx` (Next.js page referencing nonexistent `LivePanel`) deleted per D-10
- Dead `/chat` WS proxy entry removed from `vite.config.js`; `/ws/chat` correctly resolves via the existing `/ws` prefix rule

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite frontend/package.json to match package-lock.json's real dependency tree** - `bfa21c3` (fix)
2. **Task 2: Regenerate lockfile, delete pages/index.tsx, remove dead /chat proxy entry** - `106475b` (fix)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified
- `frontend/package.json` - Rewritten to optimus-prime-ui 2.0.0, real Vite/Vitest/Testing-Library toolchain; next/socket.io-client/zustand removed
- `frontend/package-lock.json` - Regenerated via `npm install` against the corrected package.json
- `frontend/vite.config.js` - Removed dead `/chat` proxy entry; `/ws` prefix (`ws: true`) and all REST proxy entries unchanged
- `frontend/pages/index.tsx` - Deleted (dead Next.js page, D-10); `pages/` directory removed
- `.gitignore` - Added `node_modules/` and `frontend/dist/` entries
- `.planning/phases/04-frontend-split/deferred-items.md` - New file logging out-of-scope npm audit findings

## Decisions Made
- Followed 04-PATTERNS.md's verbatim target manifest for `package.json` — no deviation in dependency versions
- Used `npm install` (not `npm ci`) to regenerate the lockfile per the plan's explicit instruction, then verified `npm ci` succeeds afterward as the acceptance test
- Did not bump `vite`/`vitest` beyond the pinned major versions, per RESEARCH.md's documented ERESOLVE conflict finding

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added node_modules/ and frontend/dist/ to .gitignore**
- **Found during:** Task 2 (npm install)
- **Issue:** Repo had no `.gitignore` entry for `node_modules/`; `npm install` left it untracked with no ignore rule, risking accidental commit of ~240 generated packages
- **Fix:** Added `node_modules/` and `frontend/dist/` to `.gitignore`
- **Files modified:** `.gitignore`
- **Verification:** `git status --short` no longer lists `frontend/node_modules/` as untracked
- **Committed in:** `106475b` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical)
**Impact on plan:** Necessary correctness fix to avoid committing generated dependency output. No scope creep.

## Issues Encountered
- `npm audit` reported 8 transitive dev-toolchain vulnerabilities (2 low, 1 moderate, 5 high) in the pinned `vite`/`postcss`/`tailwindcss` dependency tree after regeneration. These are all in the exact pinned major versions RESEARCH.md verified as mutually compatible (a newer major produces a real ERESOLVE peer conflict in this sandbox), and mostly affect the local dev server only (not the built production bundle). Logged to `.planning/phases/04-frontend-split/deferred-items.md` rather than fixed — out of this plan's scope per the plan's explicit "do not bump major versions" instruction.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Frontend toolchain is now buildable/testable: `npm ci` succeeds, `npm run test` invokes vitest, `npx vitest run` passes 8/8 existing tests
- This plan was BLOCKING for the rest of Phase 4 (D-10 escalation, RESEARCH.md Pitfall 1) — all downstream Phase 4 plans (04-02 through 04-07) can now run their test suites
- No blockers identified for downstream plans

---
*Phase: 04-frontend-split*
*Completed: 2026-09-04*

## Self-Check: PASSED

- FOUND: frontend/package.json
- FOUND: frontend/package-lock.json
- FOUND: frontend/vite.config.js
- CONFIRMED DELETED: frontend/pages/index.tsx
- FOUND: .planning/phases/04-frontend-split/deferred-items.md
- FOUND: .planning/phases/04-frontend-split/04-01-SUMMARY.md
- FOUND commit: bfa21c3 (Task 1)
- FOUND commit: 106475b (Task 2)
