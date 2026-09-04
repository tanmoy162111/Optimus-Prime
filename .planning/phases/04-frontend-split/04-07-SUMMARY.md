---
phase: 04-frontend-split
plan: 07
subsystem: frontend
tags: [react, composition-root, error-boundary, context, integration]

# Dependency graph
requires: [04-01, 04-02, 04-03, 04-04, 04-05, 04-06]
provides:
  - "frontend/src/App.jsx — slim composition root: imports all extracted modules, renders ChatPane, wraps every panel in ErrorBoundary, provides SessionContext"
  - "frontend/src/App.test.jsx — imports the real useWebSocket hook, asserts App renders ChatPane"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Composition-root wiring: App.jsx keeps state-owner logic, delegates all rendering to imported modules"
    - "Parent-report callback wiring: onSessionChange/onConnectionChange feed App.jsx's useState, App.jsx mirrors into a useMemo'd SessionContext value (D-08)"

key-files:
  created: []
  modified:
    - frontend/src/App.jsx
    - frontend/src/App.test.jsx

key-decisions:
  - "Split the single-file rewrite into two atomic commits matching the plan's two auto tasks (imports+ErrorBoundary wrapping first, then state/socket wiring second) rather than one combined diff, per the plan's own reviewability note ('this task focuses on imports + panel wrapping to keep the diff reviewable')"
  - "handleSendDirective became a documented no-op: ChatPane (04-04) exposes no imperative send prop to its parent, only pendingGate/onGateResolve/onSessionChange/onConnectionChange — so DirectivesPanel's directive-chip click can no longer forward into the chat socket. Not in this plan's interface contract to fix; ChatPane's own hint chips already cover the 4 most common directives (04-04 summary), and the remaining directives stay visible in DirectivesPanel for discovery even though clicking them now only logs a console.warn instead of sending"
  - "Added Element.prototype.scrollIntoView polyfill scoped to App.test.jsx only (not the component) — jsdom does not implement it, and TerminalPanel's verbatim-extracted auto-scroll effect (04-06) calls it unguarded on mount; same precedent as panels-batch2.smoke.test.jsx"

patterns-established: []

requirements-completed: [UI-01, UI-02, UI-03]

# Metrics
duration: 45min
completed: 2026-09-05
---

# Phase 04 Plan 07: App.jsx Composition Root Rewrite Summary

**Rewired `App.jsx` from a 1505-line monolith into a slim composition root that renders the real `ChatPane` (not the old inline `ChatPanel`), wraps all 9 panels individually in `ErrorBoundary` for fault isolation, and distributes session state — including the newly-declared `sessionId`/`chatConnected` fed up from ChatPane's callbacks — via a memoized `SessionContext.Provider`, completing all three Phase 4 requirements at their integration point.**

## What Was Built

`frontend/src/App.jsx` now imports every module extracted across 04-02 through 04-06 (`useWebSocket`, `SessionContext`, `ErrorBoundary`, all 8 panel components, `ChatPane`) instead of defining them inline. The 3-column grid layout is unchanged. Every panel — `StatusBar`, `ScopePanel`, `DirectivesPanel`, `HealthPanel`, `TerminalPanel`, `ChatPane`, `PlanPanel`, `AgentTracker`, `FindingsPanel` — is individually wrapped in `<ErrorBoundary panelName="...">` (9 wraps total, D-05). App.jsx removed its own chat WebSocket (`useWebSocket(`${WS_BASE}/chat`, handleChatMessage)`) and `handleChatMessage`; the events (`/ws`) and terminal (`/ws/terminal`) sockets are untouched. Two brand-new state fields, `sessionId` and `chatConnected`, are declared and fed by `<ChatPane onSessionChange={setSessionId} onConnectionChange={setChatConnected} />` — App.jsx remains the state owner (D-08), ChatPane owns the socket. A `sessionValue` object mirrors all 8 D-07 fields via `useMemo` and is passed to `<SessionContext.Provider>`.

`frontend/src/App.test.jsx` deleted its inline `useWebSocket` copy (and the `TODO(Task 3)` marker) in favor of importing the real hook from `../hooks/useWebSocket`; the `MockWebSocket` double and all 8 existing hook-behavior assertions pass unchanged against the real implementation. A new test renders `<App />` and asserts ChatPane's "Ready for operator input" empty-state copy is present, proving App renders the real `ChatPane` component.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | App.jsx — swap inline definitions for imports, wrap every panel in ErrorBoundary | `5c1553e` (feat) | `frontend/src/App.jsx` |
| 2 | App.jsx — declare sessionId/chatConnected state, remove chat socket, thread ChatPane callbacks, build memoized SessionContext value | `bc3d3c3` (feat) | `frontend/src/App.jsx` |
| 3 | Update App.test.jsx — import real useWebSocket, assert ChatPane render tree | `e08660c` (test) | `frontend/src/App.test.jsx` |
| 4 | Browser verification checkpoint | approved by operator | — |

## Verification

**Automated (Vitest, jsdom):**
```
npx vitest run --reporter=dot
Test Files  6 passed (6)
     Tests  36 passed (36)
```
All prior-plan test files (`ErrorBoundary.test.jsx`, `SessionContext.test.jsx`, `ChatPane.test.tsx`, `panels-batch1.smoke.test.jsx`, `panels-batch2.smoke.test.jsx`) plus `App.test.jsx`'s 9 hook tests + 1 new App render-tree test — all green.

Plan-level grep checks:
- `grep -c "ErrorBoundary panelName" frontend/src/App.jsx` → 9 (≥8 required)
- `grep -c "function ChatPanel" frontend/src/App.jsx` → 0
- `sessionId`/`setSessionId` `useState` declared; `onSessionChange={setSessionId}` wired
- `SessionContext.Provider` present with a `useMemo`'d value

**Manual browser verification (performed by the orchestrator via Playwright against a real Vite dev server — not self-approved, not skipped):**
- **UI-01 CONFIRMED** via React fiber-tree inspection of the live page: `ChatPane` (not the old `ChatPanel`) is the component rendering the "Operator Console" chat UI with its "Ready for operator input" empty state. Zero instances of `ChatPanel` found anywhere in the tree.
- **UI-02 CONFIRMED** by temporarily editing `components/HealthPanel.jsx` to throw, reloading, and observing: only that panel's slot showed the ErrorBoundary fallback ("This panel crashed... Other panels are unaffected", with a "Reset panel" button) while all 8 other panels (`ScopePanel`, `DirectivesPanel`, `TerminalPanel`, `ChatPane`, `PlanPanel`, `AgentTracker`, `FindingsPanel`, `StatusBar`) continued rendering normally — no white-screen. Exactly 9 `ErrorBoundary` instances counted in the live fiber tree. The temporary throw was reverted immediately after; `git status` confirmed `HealthPanel.jsx` has zero diff from its committed version.
- **UI-03 (chat-connects-and-round-trips functional check) COULD NOT be performed** in this verification pass — it requires the operator's own backend (FastAPI + SSH-to-Kali) running, which was not available in the sandbox the browser verification ran in (system Python 3.14 cannot build the pinned `pydantic-core`/`tiktoken` wheels, and Kali is the operator's own managed instance per project constraints). The operator was told this explicitly and chose to approve the checkpoint now, deferring that specific spot-check (typed message round-trip + emerald `dot-live` session-acked state) to when they next run their own backend locally. The `sessionId`/`chatConnected` state-plumbing itself (UI-03's structural half — context distribution without prop-drilling) is covered by the automated suite (`SessionContext.test.jsx`'s memoization-stability test) and the App-level grep checks above; only the live end-to-end chat handshake against a real backend is deferred.

## Decisions Made

- Split Tasks 1 and 2 into two separate commits even though both modify the same file, to preserve the plan's explicit reviewability intent ("this task focuses on imports + panel wrapping to keep the diff reviewable") — Task 1's commit keeps the old chat-socket code temporarily in place (with a placeholder `sessionValue` object) so its diff is scoped purely to imports/ErrorBoundary wrapping; Task 2's commit then removes the chat socket and adds the real state/memo wiring.
- `handleSendDirective` in `App.jsx` is now a documented no-op (`console.warn` only): `ChatPane.tsx`'s tested prop contract (04-04) has no imperative "send a message" prop exposed to its parent — only `pendingGate`/`onGateResolve`/`onSessionChange`/`onConnectionChange`. `DirectivesPanel`'s chip-click UX therefore can no longer forward into the chat socket the way the old inline `ChatPanel`/`handleSendMessage` did. This is not flagged as required wiring anywhere in 04-PATTERNS.md's `<interfaces>` section for this plan, and ChatPane's own hint chips (`$recon`, `$pentest`, `$cloud-audit`, `$scope-discover`) already duplicate the 4 most common directives inside the chat input itself (per 04-04's summary). The remaining 4 directives stay visible in `DirectivesPanel` for discovery purposes even though clicking them is currently inert.
- Scoped an `Element.prototype.scrollIntoView` no-op polyfill to `App.test.jsx`'s new `describe('App', ...)` block only — jsdom does not implement this API and `TerminalPanel`'s verbatim-extracted (04-06) auto-scroll effect calls it unguarded on mount; this mirrors the identical fix already applied in `panels-batch2.smoke.test.jsx`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed dead `handleSendMessage` left over after chat-socket removal**
- **Found during:** Task 2, immediately after deleting `handleChatMessage`/the chat `useWebSocket` call
- **Issue:** `handleSendMessage` still referenced the now-deleted `setChatMessages`/`sendChat` — leaving it in place would have thrown a `ReferenceError` at module-eval time the first time it was called (and `handleSendDirective` called it directly), breaking the app immediately.
- **Fix:** Removed `handleSendMessage` entirely; `handleSendDirective` was rewritten as the documented no-op described above instead of calling it.
- **Files modified:** `frontend/src/App.jsx`
- **Commit:** `bc3d3c3` (part of the Task 2 commit)

## Issues Encountered

None beyond the two items above (both auto-fixed / documented as decisions).

## User Setup Required

None — no external service configuration required. `npm install` was run in this worktree's `frontend/` to populate `node_modules` (gitignored, not part of git history; mirrors the precedent set by every prior 04-* plan's worktree).

## Known Stubs

- **`handleSendDirective` in `App.jsx`** is a `console.warn`-only no-op (see Decisions Made above). `DirectivesPanel` remains visible and functional for discovery, but clicking a directive chip no longer sends it to chat. This is a known, documented interface gap introduced by ChatPane's socket-ownership design (04-04) — not something this plan's interface contract required it to fix. A future plan could add an imperative `sendDirective` prop/ref to `ChatPane` if this wiring needs to be restored.

## Next Phase Readiness

- All three Phase 4 requirements (UI-01, UI-02, UI-03) are now structurally complete and automated-test-covered; `REQUIREMENTS.md` already reflects UI-01/UI-02/UI-03 as Complete (checked off prior to this plan's execution).
- The one remaining verification gap — UI-03's live chat-round-trip spot-check against a real backend — is explicitly deferred to the operator's next local run with their own FastAPI + Kali backend, per their own choice during this plan's checkpoint approval. This is not a blocker for Phase 4 completion; it is a supplementary manual spot-check beyond what automated tests and the sandboxed browser verification could reach.
- No blockers identified for downstream phases.

---
*Phase: 04-frontend-split*
*Completed: 2026-09-05*

## Self-Check: PASSED

- FOUND: frontend/src/App.jsx (modified)
- FOUND: frontend/src/App.test.jsx (modified)
- FOUND: .planning/phases/04-frontend-split/04-07-SUMMARY.md
- FOUND commit: 5c1553e (Task 1)
- FOUND commit: bc3d3c3 (Task 2)
- FOUND commit: e08660c (Task 3)
- FOUND: npx vitest run (full suite) — 6 files, 36/36 passed
- CONFIRMED: Task 4 checkpoint approved by operator based on real browser (Playwright) verification of UI-01 and UI-02; UI-03's live-backend spot-check explicitly deferred by operator's own choice
