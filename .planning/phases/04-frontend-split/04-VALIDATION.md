---
phase: 04
slug: frontend-split
status: draft
nyquist_compliant: false
wave_0_complete: false
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
| **Quick run command** | `cd frontend && npx vitest run --reporter=dot` (a `"test": "vitest run"` script is currently missing from `package.json` entirely — Wave 0 adds it) |
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

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | 0 | — | — | `frontend/package.json`/`package-lock.json` resolve to the real Vite/Vitest/React toolchain, `npm ci` succeeds | build | `cd frontend && npm ci` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-01 | T-04-WS-AUTH | `ChatPane.tsx` sends `{type:"init",...}` with `?token=` on connect; transitions to "connected" only after `{type:"session"}` ack | unit | `npx vitest run frontend/components/ChatPane.test.tsx` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-01 | — | `ChatPane.tsx` routes `{chunk,done}` vs `{type:...}` control frames vs `{event_type:...}` Clawhip events correctly (no shape assumed present) | unit | `npx vitest run frontend/components/ChatPane.test.tsx` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-01 | — | `App.jsx` renders `<ChatPane />`, not the old inline `ChatPanel` | unit/integration | `npx vitest run frontend/src/App.test.jsx` | ⚠️ partial — `App.test.jsx` exists but needs a render-tree assertion added | ⬜ pending |
| TBD | TBD | TBD | UI-02 | — | Error boundary catches a thrown error from a panel, renders the locked fallback markup, sibling panels keep rendering | unit | `npx vitest run frontend/components/ErrorBoundary.test.jsx` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-02 | — | `TerminalPanel`/`FindingsPanel`/`ScopePanel` exist as standalone files, independently importable | unit | `npx vitest run frontend/components/*.test.jsx` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-03 | — | A component nested under `SessionContext.Provider` reads session state via `useContext(SessionContext)` without prop-drilling | unit | `npx vitest run frontend/context/SessionContext.test.jsx` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | UI-03 | — | `SessionContext`'s value is memoized — no new object reference on unrelated `App.jsx` re-renders | unit | `npx vitest run frontend/context/SessionContext.test.jsx` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Task ID / Plan / Wave columns are TBD — the planner fills these in once PLAN.md files exist; the requirement/behavior/command mapping above is locked from RESEARCH.md.*

---

## Wave 0 Requirements

- [ ] `frontend/package.json` + `frontend/package-lock.json` dependency fix (D-10 escalation, RESEARCH.md Pitfall 1) — `npm ci` currently fails (`EUSAGE`); lockfile `name` field is `"optimus-prime-ui"`, mismatched with `package.json`'s `"optimus-frontend"`. Nothing else in this table can run until this is fixed.
- [ ] `"test": "vitest run"` script added to `package.json` — currently absent
- [ ] `frontend/components/ChatPane.test.tsx` — new file, covers UI-01 handshake/routing behavior
- [ ] `frontend/components/ErrorBoundary.test.jsx` — new file, covers UI-02 fault isolation
- [ ] `frontend/context/SessionContext.test.jsx` — new file, covers UI-03 context access + memoization
- [ ] `frontend/src/App.test.jsx` updated to import the real `frontend/hooks/useWebSocket.js` (delete the inline `TODO(Task 3)` duplicate copy) and add a render-tree assertion that `ChatPane` (not the old inline `ChatPanel`) is what's rendered

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Chat interface visible in browser is served by `ChatPane.tsx` | UI-01 | ROADMAP success criterion requires React DevTools component-tree confirmation — not assertable by a jsdom unit test | Open the app in a browser, open React DevTools, expand the component tree, confirm `ChatPane` (not `ChatPanel`) wraps the visible chat UI |
| Deliberately throwing an error in one panel does not crash the others | UI-02 | Requires visually confirming the browser doesn't white-screen and sibling panels keep rendering, alongside the automated unit test | Temporarily throw in one extracted panel (e.g. via a dev-only trigger), reload, confirm the error boundary fallback renders in that panel's slot while other panels remain interactive |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 20s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
