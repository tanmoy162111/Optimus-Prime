# Phase 4: Frontend Split - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-09-02
**Phase:** 04-frontend-split
**Areas discussed:** Chat implementation, Extraction scope, SessionContext scope, Next.js cleanup, WS hook extraction, File-type convention, Connection status shape

---

## Chat implementation

| Option | Description | Selected |
|--------|-------------|----------|
| Rewrite ChatPane.tsx | Drop socket.io-client + style jsx, implement raw WS init/session/chat handshake, port feature parity from inline ChatPanel | ✓ |
| Promote the working inline ChatPanel | Move current inline ChatPanel into ChatPane.tsx as-is, minimal rewrite risk | |
| Something else | Free text | |

**User's choice:** Rewrite ChatPane.tsx (recommended)
**Notes:** Discovered during codebase scouting: the backend's `/chat` WS handler (since commit 7f9efad) requires an init→session→chat handshake that the current frontend never sends — operator chat via the browser has likely been non-functional since that commit. The rewrite folds in fixing this protocol gap.

---

## Extraction scope

| Option | Description | Selected |
|--------|-------------|----------|
| Only the 3 named panels | TerminalPanel/FindingsPanel/ScopePanel only, matches literal requirement text | |
| Full componentization | Extract every inline sub-component in App.jsx into separate files | ✓ |

**User's choice:** Full componentization

---

## SessionContext scope

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal: id + connection status | SessionContext holds only session_id + WS connection status | |
| Broader: also scope + plan + engagement state | Absorbs scope, currentPlan, engagementActive/Start too | ✓ |

**User's choice:** Broader — also scope + plan + engagement state

---

## Next.js cleanup

| Option | Description | Selected |
|--------|-------------|----------|
| Clean it up | Delete dead pages/index.tsx, fix package.json scripts to Vite | ✓ |
| Leave it alone | Out of scope, don't touch | |

**User's choice:** Clean it up

---

## Error boundary granularity (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Every extracted panel | All new components get error boundaries | ✓ |
| Only the 3 named panels | Only TerminalPanel/FindingsPanel/ScopePanel wrapped | |

**User's choice:** Every extracted panel

---

## State ownership (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Context is single source of truth | Move useState hooks into SessionProvider entirely | |
| App.jsx keeps state, context mirrors it | Smaller diff, App.jsx state and context both represent same values | ✓ |

**User's choice:** App.jsx keeps state, context mirrors it (not the recommended option — deliberate smaller-diff choice)

---

## Session init behavior (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-init on connect, no UI | Silent init/session handshake on WS open, session_id persisted in localStorage | ✓ |
| Explicit "Start Session" action | Operator-initiated button before chat is usable | |

**User's choice:** Auto-init on connect, no UI

---

## WS hook extraction (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| Extract to frontend/hooks/useWebSocket.js | Shared module, removes duplication with App.test.jsx | ✓ |
| Leave it inline in App.jsx | Extracted panels get their own independent implementations | |

**User's choice:** Extract to frontend/hooks/useWebSocket.js

---

## File-type convention (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| .jsx — match App.jsx | New panels stay plain JS, ChatPane.tsx remains the sole TS exception | ✓ |
| .tsx — match ChatPane.tsx | Convert all new components to TypeScript | |

**User's choice:** .jsx — match App.jsx

---

## Connection status shape (follow-up)

| Option | Description | Selected |
|--------|-------------|----------|
| All three, named per-socket | { chatConnected, eventsConnected, terminalConnected } in context | ✓ |
| Just chat connection | Only chat socket state tracked in context | |

**User's choice:** All three, named per-socket

---

## Claude's Discretion

- Exact error boundary implementation (no existing ErrorBoundary component to follow)
- Whether `/terminal/exec` becomes session-scoped
- Layout/grid CSS structure when panels move to separate files
- Whether the REST `/api/chat` fallback needs any frontend usage

## Deferred Ideas

- Converting the rest of the frontend to TypeScript
- Making SessionContext the single source of truth (superseded App.jsx state entirely)
- Wiring `/terminal/exec` to be session-scoped (backend change)
- Wiring up the REST `/api/chat` fallback path from the frontend
