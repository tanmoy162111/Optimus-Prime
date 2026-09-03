---
phase: 04
slug: frontend-split
status: planned
nyquist_compliant: true
wave_0_complete: true
created: 2026-09-04
---

# Phase 04 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest ^4.1.3 (already configured in `frontend/vite.config.js`'s `test` block: `environment: 'jsdom'`, `globals: true`, `setupFiles: ['./src/test-setup.js']`, `passWithNoTests: true`) |
| **Config file** | `frontend/vite.config.js` (embedded `test` key — no separate `vitest.config.js`) |
| **Quick run command** | `cd frontend && npx vitest run --reporter=dot` (04-01 Task 1 adds the missing `"test": "vitest run"` script to `package.json`) |
| **Full suite command** | `cd frontend && npx vitest run` |
| **Estimated runtime** | ~10-20 seconds (small test suite today) |

---

## Sampling Rate

- **After every task commit:** Run `cd frontend && npx vitest run <changed-file>.test.jsx` (targeted)
- **After every plan wave:** Run `cd frontend && npx vitest run` (full suite)
- **Before `/gsd:verify-work`:** Full suite must be green, plus a manual browser check of UI-01's React DevTools component-tree criterion (automated tests cannot inspect DevTools)
- **Max feedback latency:** ~20 seconds

---

## Per-Task Verification Map

> Plan/Task/Wave IDs filled in now that all 7 PLAN.md files exist. Every listed task carries a concrete `<automated>` verify command (no MISSING placeholders, no watch-mode flags). Status ⬜ = execution pending (planning-time contract).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|--------|
| 04-01-T1/T2 | 04-01 | 1 | — | T-04-SC | `frontend/package.json`/`package-lock.json` resolve to the real Vite/Vitest/React toolchain; `npm ci` succeeds | build | `cd frontend && npm ci` | ⬜ pending |
| 04-04-T2 | 04-04 | 3 | UI-01 | T-04-WS-AUTH | `ChatPane.tsx` sends `{type:"init",...}` with `?token=` on connect; transitions to "connected" only after `{type:"session"}` ack | unit | `cd frontend && npx vitest run components/ChatPane.test.tsx` | ⬜ pending |
| 04-04-T2 | 04-04 | 3 | UI-01 | T-04-04b | `ChatPane.tsx` routes `{chunk,done}` vs `{type:...}` control frames vs `{event_type:...}` Clawhip events correctly (no shape assumed present) | unit | `cd frontend && npx vitest run components/ChatPane.test.tsx` | ⬜ pending |
| 04-04-T2 | 04-04 | 3 | UI-03 | T-04-03c | `ChatPane.tsx` reports session_id + acked status up via `onSessionChange`/`onConnectionChange`; optional props, no crash when omitted | unit | `cd frontend && npx vitest run components/ChatPane.test.tsx` | ⬜ pending |
| 04-07-T2/T3 | 04-07 | 4 | UI-01, UI-03 | T-04-03c | `App.jsx` declares `sessionId`/`chatConnected` useState fed by ChatPane callbacks; renders `<ChatPane />`, not the old inline `ChatPanel` | unit/integration | `cd frontend && npx vitest run src/App.test.jsx` | ⬜ pending |
| 04-03-T1 | 04-03 | 2 | UI-02 | T-04-04c | Error boundary catches a thrown error from a panel, renders the locked fallback markup, sibling panels keep rendering | unit | `cd frontend && npx vitest run components/ErrorBoundary.test.jsx` | ⬜ pending |
| 04-05-T2 / 04-06-T2 | 04-05, 04-06 | 3 | UI-02 | — | `TerminalPanel`/`FindingsPanel`/`ScopePanel` (+ all other panels) exist as standalone files, independently importable | unit | `cd frontend && npx vitest run components/panels-batch1.smoke.test.jsx components/panels-batch2.smoke.test.jsx` | ⬜ pending |
| 04-03-T2 | 04-03 | 2 | UI-03 | — | A component nested under `SessionContext.Provider` reads session state via `useContext(SessionContext)` without prop-drilling | unit | `cd frontend && npx vitest run context/SessionContext.test.jsx` | ⬜ pending |
| 04-03-T2 | 04-03 | 2 | UI-03 | — | `SessionContext`'s value is memoized — no new object reference on unrelated `App.jsx` re-renders | unit | `cd frontend && npx vitest run context/SessionContext.test.jsx` | ⬜ pending |
| 04-07-T1 | 04-07 | 4 | UI-02 | T-04-04c | `App.jsx` wraps every panel individually in `<ErrorBoundary panelName=...>` (≥8 wraps) | unit/static | `cd frontend && npx vitest run src/App.test.jsx` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Sampling continuity: no 3 consecutive tasks across the wave order (1→2→3→4) lack an automated verify — every task above has a concrete command.*

---

## Wave 0 Requirements

> Wave 0 = the test-scaffolding + toolchain-fix work that everything else depends on. All items below are now assigned to concrete plan tasks (complete = planned with a concrete automated verify).

- [x] `frontend/package.json` + `frontend/package-lock.json` dependency fix (D-10 escalation, RESEARCH.md Pitfall 1) — planned in **04-01 Task 1 + Task 2** (`npm ci` must succeed; lockfile `name` reconciled to `optimus-prime-ui`).
- [x] `"test": "vitest run"` script added to `package.json` — planned in **04-01 Task 1**.
- [x] `frontend/components/ChatPane.test.tsx` — created in **04-04 Task 2** (covers UI-01 handshake/routing + parent-callback behaviors 1-7).
- [x] `frontend/components/ErrorBoundary.test.jsx` — created in **04-03 Task 1** (covers UI-02 fault isolation).
- [x] `frontend/context/SessionContext.test.jsx` — created in **04-03 Task 2** (covers UI-03 context access + memoization).
- [x] `frontend/src/App.test.jsx` updated to import the real `frontend/hooks/useWebSocket.js` (delete the inline `TODO(Task 3)` duplicate copy) and add a render-tree assertion that `ChatPane` (not the old inline `ChatPanel`) is rendered — planned in **04-07 Task 3**.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Chat interface visible in browser is served by `ChatPane.tsx` | UI-01 | ROADMAP success criterion requires React DevTools component-tree confirmation — not assertable by a jsdom unit test | Open the app in a browser, open React DevTools, expand the component tree, confirm `ChatPane` (not `ChatPanel`) wraps the visible chat UI |
| Deliberately throwing an error in one panel does not crash the others | UI-02 | Requires visually confirming the browser doesn't white-screen and sibling panels keep rendering, alongside the automated unit test | Temporarily throw in one extracted panel (e.g. via a dev-only trigger), reload, confirm the error boundary fallback renders in that panel's slot while other panels remain interactive |

*Both manual checks are covered by 04-07's blocking `checkpoint:human-verify` (Task 4).*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 20s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved
</content>
