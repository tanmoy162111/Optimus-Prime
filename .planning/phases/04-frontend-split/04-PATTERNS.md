# Phase 4: Frontend Split - Pattern Map

**Mapped:** 2026-09-04
**Files analyzed:** 22
**Analogs found:** 19 / 22 (3 genuinely new patterns with no in-repo precedent — ErrorBoundary, SessionContext, and the multi-shape WS message router)

**Key fact driving this entire map:** Almost every file in this phase is a **verbatim extraction** from one already-existing, already-correct source file: `frontend/src/App.jsx` (1505 lines, read in full). The "closest analog" for nearly every new file is therefore a specific, cited line range of `App.jsx` itself — not a different file. Copy the JSX/logic exactly; only the module boundary (imports/exports/props) changes.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `frontend/components/ChatPane.tsx` | component | streaming + request-response (WS handshake) | `App.jsx` `ChatPanel`/`ChatMessage` (lines 1015-1179) + `useWebSocket` (lines 66-184) | role-match (protocol is net-new, UI markup is exact) |
| `frontend/components/ChatMessage.jsx` | component | transform | `App.jsx` lines 1129-1179 | exact (pure extraction) |
| `frontend/components/StatusBar.jsx` | component | transform | `App.jsx` lines 188-254 (+ `EngagementTimer` 256-263) | exact |
| `frontend/components/ScopePanel.jsx` | component | CRUD (REST POST `/scope`) | `App.jsx` lines 265-375 | exact |
| `frontend/components/DirectivesPanel.jsx` | component | event-driven | `App.jsx` lines 377-420 | exact |
| `frontend/components/TerminalPanel.jsx` | component | streaming (WS) | `App.jsx` lines 610-673 | exact |
| `frontend/components/TerminalLine.jsx` | component | transform | `App.jsx` lines 483-536 | exact |
| `frontend/components/TerminalInput.jsx` | component | request-response (REST POST `/terminal/exec`) | `App.jsx` lines 538-608 | exact |
| `frontend/components/FindingsPanel.jsx` | component | CRUD + file-I/O (report download) | `App.jsx` lines 675-872 | exact |
| `frontend/components/AgentTracker.jsx` | component | event-driven | `App.jsx` lines 874-927 | exact |
| `frontend/components/PlanPanel.jsx` | component | transform | `App.jsx` lines 929-1013 | exact |
| `frontend/components/HealthPanel.jsx` | component | request-response | `App.jsx` lines 1181-1221 | exact |
| `frontend/components/ErrorBoundary.jsx` | component (class) | event-driven (catches render errors) | none in repo | no analog — use RESEARCH.md Pattern 1 verbatim (already React-canonical, UI-SPEC-locked markup) |
| `frontend/context/SessionContext.jsx` | provider | pub-sub | none in repo | no analog — use RESEARCH.md Pattern 2 verbatim |
| `frontend/hooks/useWebSocket.js` | hook | streaming | `App.jsx` lines 66-184 (identical to `App.test.jsx` lines 47-163 inline copy) | exact (relocation only, zero behavior change) |
| `frontend/lib/constants.js` | config/utility | transform | `App.jsx` lines 15-52 | exact |
| `frontend/lib/format.js` | utility | transform | `App.jsx` lines 54-63 (`fmtTime`/`fmtElapsed`) + lines 459-479 (`renderPayload`) | exact |
| `frontend/src/App.jsx` (rewrite) | component (composition root) | event-driven | itself (current monolith, lines 1224-1505 = state + layout to keep) | exact (same file, slimmed) |
| `frontend/src/App.test.jsx` (modify) | test | — | itself (lines 1-163, the inline `useWebSocket` copy with `TODO(Task 3)` marker) | exact |
| `frontend/pages/index.tsx` | — (deleted) | — | — | n/a — delete, no replacement |
| `frontend/package.json` | config | — | `frontend/package-lock.json` `packages[""]` block (source of truth for correct deps) | exact |
| `frontend/vite.config.js` (minor edit) | config | — | itself, remove dead `/chat` proxy entry (lines 21-25) | exact |

## Pattern Assignments

### `frontend/components/ChatPane.tsx` (component, streaming + request-response)

**Analogs:** `frontend/src/App.jsx` lines 1015-1179 (`ChatPanel`/`ChatMessage` — feature/markup reference) + lines 66-184 (`useWebSocket` — connection reference) + `frontend/components/ChatPane.tsx` current file (structure/shape to replace, NOT protocol) + `backend/api/ws_handler.py` (protocol contract, read-only, do not modify)

**Imports pattern to replace** (current, broken — `ChatPane.tsx` lines 1-2):
```typescript
import { useState, useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';
```
Replace with plain `WebSocket` (browser global, no import) + the shared hook:
```typescript
import { useState, useRef, useCallback } from 'react'
import { useWebSocket } from '../hooks/useWebSocket'
```

**Auth/URL pattern (new — no existing analog, backend-contract-driven):**
```typescript
// Source: backend/app.py include_router(ws_handler.router, prefix="/ws");
// backend/api/ws_handler.py @router.websocket("/chat") => real path is /ws/chat
// backend/auth.py verify_ws_token() requires ?token=
const WS_BASE = `ws://${window.location.host}`
const token = import.meta.env.VITE_BEARER_TOKEN || 'dev-token'
const chatUrl = `${WS_BASE}/ws/chat?token=${encodeURIComponent(token)}`
```

**Handshake pattern (new, D-02/D-03 — replaces current `socket.emit('init', ...)` at ChatPane.tsx line 30):**
```typescript
// On WS open, per backend/api/ws_handler.py's expected sequence:
// welcome (server, no action needed) -> client sends {type:'init', session_id} ->
// server replies {type:'session', session_id} -> only then send {type:'chat', message}
ws.onopen = () => {
  const storedId = localStorage.getItem('session_id')
  ws.send(JSON.stringify({ type: 'init', session_id: storedId || null }))
}
```

**Core message-router pattern (new — RESEARCH.md Pattern 3, verified against `backend/api/ws_handler.py` + `backend/agent/clawhip.py`):**
```typescript
// frontend/components/ChatPane.tsx — three shapes on one socket, branch on key presence, not data.type
function handleSocketMessage(data: any) {
  if (data.type) {
    switch (data.type) {
      case 'session':
        localStorage.setItem('session_id', data.session_id)
        setSessionAcked(true)   // "connected" = session-acked, per UI-SPEC, not merely socket-open
        break
      case 'error':
        // one-time system ChatMessage, red bubble — see Copywriting Contract in 04-UI-SPEC.md
        break
      // 'welcome' / 'pong' — no UI action needed
    }
    return
  }
  if ('chunk' in data || 'done' in data) {
    // chat stream fragment — append to last assistant message, exactly like
    // App.jsx's handleChatMessage (lines 1347-1377) already accumulates content
    return
  }
  if (data.event_type) {
    // Clawhip lifecycle event on the SAME socket (PHASE_FAILED/GATE_PENDING etc.)
    // per D-12: render inline system/error-style message for PHASE_FAILED/GATE_PENDING,
    // no-op otherwise — do not let it fall through to chat-content rendering
  }
}
```

**Feature-parity markup to port verbatim** (`App.jsx` lines 1042-1127, `ChatPanel` function): panel-header shape with `dot-live`/red-disconnected states, pending-gate confirm/skip pill buttons (lines 1057-1074), message list + `ChatMessage` (lines 1129-1179), directive hint chips (lines 1093-1104), input + send button (lines 1106-1124). Reuse `ChatMessage` as its own extracted component (see below) rather than re-inlining it in `ChatPane.tsx`.

**Error handling pattern:** Reuse the existing `useWebSocket` hook's built-in try/catch + exponential backoff (`App.jsx` lines 88-181) rather than writing new reconnect logic — `ChatPane.tsx` should call `useWebSocket(chatUrl, handleSocketMessage)` exactly as `App.jsx` currently calls it for its three sockets (lines 1379-1392).

---

### `frontend/components/ChatMessage.jsx` (component, transform)

**Analog:** `frontend/src/App.jsx` lines 1129-1179

**Core pattern (extract verbatim, only the module boundary changes):**
```jsx
// frontend/components/ChatMessage.jsx
import { Shield, Layers } from 'lucide-react'

export default function ChatMessage({ msg }) {
  const isUser = msg.role === 'user'
  const isError = msg.type === 'error'
  const isPlan  = msg.type === 'plan'
  // ...body identical to App.jsx lines 1134-1178, unchanged...
}
```
No new logic — this is a pure presentational extraction. Do not add prop-types or convert to `.tsx` (D-06 — stays `.jsx`).

---

### `frontend/components/StatusBar.jsx` (component, transform)

**Analog:** `frontend/src/App.jsx` lines 188-263 (`StatusBar` + its `EngagementTimer` sub-component)

**Core pattern:** Extract both `StatusBar` and `EngagementTimer` into this one file (co-located, matching how `TerminalPanel` co-locates `TerminalLine`/`TerminalInput` per D-04's explicit note "`+ its TerminalLine/TerminalInput sub-parts`"). Props change from local state to reading `chatConnected`/`eventsConnected`/`terminalConnected` off `SessionContext` where convenient, OR keep receiving them as props from `App.jsx` (D-08 allows either — App.jsx remains the state owner either way). Recommended: keep prop-based for `StatusBar` since it is rendered once at the top of the tree, same call-site pattern as today (`App.jsx` lines 1442-1448).

---

### `frontend/components/ScopePanel.jsx` (component, CRUD)

**Analog:** `frontend/src/App.jsx` lines 265-375

**Core pattern (local form state + REST POST, extract verbatim):**
```jsx
export default function ScopePanel({ scope, onSetScope }) {
  const [targets, setTargets] = useState(scope?.targets?.join(', ') || '')
  // ...identical body to App.jsx lines 266-372...
}
```
`onSetScope` stays a callback prop wired from `App.jsx`'s `handleSetScope` (lines 1412-1426), which calls `fetch('/scope', { method: 'POST', ... })` — this REST call pattern is the one to reuse for any other REST-backed panel (`FindingsPanel`'s report download, `TerminalInput`'s exec call, `handleGateResolve`).

---

### `frontend/components/DirectivesPanel.jsx` (component, event-driven)

**Analog:** `frontend/src/App.jsx` lines 377-420

**Core pattern:** Extract verbatim, including the local `icons` map keyed by directive string. `onSendDirective` prop wired to `App.jsx`'s `handleSendDirective` (lines 1407-1409), which calls `handleSendMessage` → `sendChat({ content: text })`. This is the reference for how any panel triggers chat-socket sends without owning the socket itself.

---

### `frontend/components/TerminalPanel.jsx` + `TerminalLine.jsx` + `TerminalInput.jsx` (component, streaming + request-response)

**Analog:** `frontend/src/App.jsx` lines 483-673 (three functions: `TerminalLine` 483-536, `TerminalInput` 538-608, `TerminalPanel` 610-673)

**Core pattern — REST fetch with error state (from `TerminalInput`, lines 544-567), the canonical "REST POST + inline error banner" pattern to copy for any new REST-triggered action:**
```jsx
const handleSubmit = async () => {
  const command = cmd.trim()
  if (!command || running) return
  setRunning(true)
  setError(null)
  try {
    const resp = await fetch('/terminal/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      setError(err.detail || `HTTP ${resp.status}`)
    } else {
      setCmd('')
    }
  } catch (e) {
    setError(String(e))
  } finally {
    setRunning(false)
    inputRef.current?.focus()
  }
}
```
**Discretion note (CONTEXT.md):** whether to pass `session_id` as an extra field in this POST body is Claude's discretion — trivial addition, backend can ignore it; not required.

**Auto-scroll pattern** (`TerminalPanel`, lines 611-626) — reuse for `ChatPane.tsx`'s message list too (both already use the identical `bottomRef`/`scrollIntoView` + scroll-position `autoScroll` toggle idiom; `ChatPanel`'s simpler version is at lines 1018-1023).

---

### `frontend/components/FindingsPanel.jsx` (component, CRUD + file-I/O)

**Analog:** `frontend/src/App.jsx` lines 675-872

**File-download pattern** (lines 682-717, the only file-I/O flow in the codebase — reuse verbatim, this is the "closest analog" for any future download feature too):
```jsx
const triggerDownload = (blob, filename) => {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

const downloadReport = async (type) => {
  setDownloading(type)
  setReportError(null)
  const filename = `report-${reportFormat}.${type}`
  const url = type === 'json' ? `/report/${reportFormat}` : `/report/${reportFormat}/${type}`
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: findings.length ? findings : undefined, framework: reportFramework }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }))
      throw new Error(err.detail || resp.statusText)
    }
    triggerDownload(await resp.blob(), filename)
  } catch (e) {
    setReportError(e.message || 'Report generation failed')
  } finally {
    setDownloading(null)
  }
}
```

---

### `frontend/components/AgentTracker.jsx` (component, event-driven)

**Analog:** `frontend/src/App.jsx` lines 874-927 — extract verbatim, `agents` prop stays sourced from `App.jsx`'s `handleEventMessage` WS handler (lines 1294-1309), unchanged.

---

### `frontend/components/PlanPanel.jsx` (component, transform)

**Analog:** `frontend/src/App.jsx` lines 929-1013 — extract verbatim, including the early-return empty state (lines 930-944). `plan` prop stays sourced from `App.jsx`'s `handleChatMessage`/`handleEventMessage` combined updates (lines 1312-1333, 1372-1376).

---

### `frontend/components/HealthPanel.jsx` (component, request-response)

**Analog:** `frontend/src/App.jsx` lines 1181-1221 — extract verbatim. `onRefresh` wired to `App.jsx`'s `fetchHealth` (lines 1243-1248), the canonical simple-GET-with-try/catch pattern:
```jsx
const fetchHealth = useCallback(async () => {
  try {
    const r = await fetch('/health')
    setHealth(await r.json())
  } catch { setHealth(null) }
}, [])
```

---

### `frontend/components/ErrorBoundary.jsx` (component, event-driven — NO in-repo analog)

**Source:** RESEARCH.md Pattern 1 (verified against React docs, no adaptation needed) + `04-UI-SPEC.md` "New UI Surface: Error Boundary Fallback" section (markup and copy locked verbatim).

**Full pattern to use as-is:**
```jsx
// frontend/components/ErrorBoundary.jsx
import { Component } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default class ErrorBoundary extends Component {
  state = { hasError: false, resetKey: 0 }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error(`[ErrorBoundary:${this.props.panelName}]`, error, info)
  }

  handleReset = () => {
    this.setState(s => ({ hasError: false, resetKey: s.resetKey + 1 }))
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="panel flex flex-col h-full">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <AlertTriangle size={13} className="text-red-400" />
              <span className="label-xs text-red-400">{this.props.panelName} — Error</span>
            </div>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center text-center px-4">
            <AlertTriangle size={22} className="text-red-500/60 mb-3" />
            <p className="font-mono text-xs text-red-400">This panel crashed</p>
            <p className="text-xs text-zinc-600 mt-1">An unexpected error stopped rendering. Other panels are unaffected.</p>
            <button className="btn-ghost text-xs px-2 py-1 mt-3 gap-1.5" onClick={this.handleReset}>
              <RefreshCw size={12} /> Reset panel
            </button>
          </div>
        </div>
      )
    }
    return <div key={this.state.resetKey}>{this.props.children}</div>
  }
}
```
Usage in `App.jsx`: `<ErrorBoundary panelName="Terminal"><TerminalPanel {...props} /></ErrorBoundary>` around every one of the 9 extracted panels (D-05 — all of them, not just the 3 ROADMAP-named ones).

---

### `frontend/context/SessionContext.jsx` (provider, pub-sub — NO in-repo analog)

**Source:** RESEARCH.md Pattern 2 (React Context docs) + D-07/D-08.

```jsx
// frontend/context/SessionContext.jsx
import { createContext, useContext } from 'react'

export const SessionContext = createContext(null)
export const useSession = () => useContext(SessionContext)
```
**Provider wiring in `App.jsx` (mirror pattern, D-08 — App.jsx keeps `useState` as source of truth):**
```jsx
const sessionValue = useMemo(() => ({
  sessionId, chatConnected, eventsConnected, terminalConnected,
  scope, currentPlan, engagementActive, engagementStart,
}), [sessionId, chatConnected, eventsConnected, terminalConnected,
     scope, currentPlan, engagementActive, engagementStart])

return (
  <SessionContext.Provider value={sessionValue}>
    {/* existing grid layout, App.jsx lines 1440-1503, unchanged structurally */}
  </SessionContext.Provider>
)
```
**Pitfall to avoid (from RESEARCH.md):** never pass an inline object literal as `value` — always `useMemo` with every mirrored field listed in the dependency array, or every consumer re-renders on unrelated `App.jsx` state changes (e.g. a new terminal line arriving).

---

### `frontend/hooks/useWebSocket.js` (hook, streaming)

**Analog:** `frontend/src/App.jsx` lines 66-184 (canonical implementation) — **identical** to the inline copy already in `frontend/src/App.test.jsx` lines 47-163, which has an explicit `TODO(Task 3): Delete this inline copy after App.jsx is updated` comment.

**Extraction instruction:** Move the function body verbatim (health-check gate, exponential backoff via `getBackoffDelay`, heartbeat via `startHeartbeat`/`stopHeartbeat`, `mountedRef` StrictMode guard, `visibilitychange` reconnect-on-wake, `lastSeq` tracking) into its own module with a named export:
```javascript
// frontend/hooks/useWebSocket.js
import { useState, useEffect, useRef, useCallback } from 'react'

export function useWebSocket(url, onMessage, enabled = true) {
  // ...body identical to App.jsx lines 67-183...
}
```
`App.jsx` then does `import { useWebSocket } from '../hooks/useWebSocket'` and calls it 3x (events, chat, terminal) exactly as today (lines 1379, 1380, 1389-1392); `ChatPane.tsx` imports the same module for its own socket. `App.test.jsx` should delete its inline copy (lines 12-163) and `import { useWebSocket } from '../hooks/useWebSocket'` instead, keeping `global.WebSocket = MockWebSocket` — the existing `MockWebSocket` test double (lines 12-38) is the pattern to reuse for `ChatPane.test.tsx`'s WS mocking too, per RESEARCH.md's "Don't Hand-Roll" table.

---

### `frontend/lib/constants.js` (config/utility, transform)

**Analog:** `frontend/src/App.jsx` lines 15-52

**Pattern (plain named exports, no default export, matching how `App.jsx` currently declares module-level consts):**
```javascript
// frontend/lib/constants.js
export const SEVERITY_MAP = { critical: {...}, high: {...}, ... }  // App.jsx lines 15-21
export const EVENT_ICONS = { ENGAGEMENT_STARTED: {...}, ... }       // App.jsx lines 23-46
export const REPORT_FORMATS_UI = [...]                              // App.jsx lines 48-51
export const REPORT_FRAMEWORKS = [...]                              // App.jsx line 52
```
Note: `EVENT_ICONS` values reference `lucide-react` icon components directly (e.g. `Zap`, `Layers`) — the import block at the top of `constants.js` must import every icon used across all `EVENT_ICONS` entries from `lucide-react`, matching `App.jsx`'s current import list (lines 2-7).

---

### `frontend/lib/format.js` (utility, transform)

**Analog:** `frontend/src/App.jsx` lines 54-63 (`fmtTime`, `fmtElapsed`) + lines 459-479 (`renderPayload`)

```javascript
// frontend/lib/format.js
export const fmtTime = (iso) => { /* App.jsx lines 54-57 */ }
export const fmtElapsed = (start) => { /* App.jsx lines 59-63 */ }
export const renderPayload = (payload) => { /* App.jsx lines 459-479 */ }
```
`renderPayload` is consumed by the extracted `EventCard`/terminal event-feed rendering if that sub-component is kept — verify at implementation time whether `EventCard` (lines 422-457) needs its own file or folds into wherever the event feed lives; `renderPayload` is its dependency either way.

---

### `frontend/src/App.jsx` (rewrite — composition root)

**Analog:** itself. Keep lines 1224-1436 (all `useState`/`useCallback`/`useEffect` state-owner logic — health/directives fetch, WS handlers, `handleSendMessage`/`handleSetScope`/`handleGateResolve`) essentially unchanged; replace the removed inline sub-component definitions (lines 188-1221) with imports from `frontend/components/*`, `frontend/hooks/useWebSocket`, `frontend/lib/constants`, `frontend/lib/format`; wrap the render tree (lines 1439-1505) in `SessionContext.Provider` and wrap every panel individually in `ErrorBoundary` per D-05.

**Import pattern (new import block replacing lines 1-7):**
```jsx
import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Shield, Activity, ... } from 'lucide-react'   // only icons App.jsx itself still uses directly (StatusBar/EngagementTimer if not extracted, or none if fully extracted)
import { useWebSocket } from '../hooks/useWebSocket'
import { SessionContext } from '../context/SessionContext'
import ErrorBoundary from '../components/ErrorBoundary'
import StatusBar from '../components/StatusBar'
import ScopePanel from '../components/ScopePanel'
import DirectivesPanel from '../components/DirectivesPanel'
import TerminalPanel from '../components/TerminalPanel'
import FindingsPanel from '../components/FindingsPanel'
import AgentTracker from '../components/AgentTracker'
import PlanPanel from '../components/PlanPanel'
import HealthPanel from '../components/HealthPanel'
import ChatPane from '../../components/ChatPane'
```
(Adjust relative path depth for `ChatPane.tsx` — it lives in `frontend/components/`, sibling to the other panels, not under `frontend/src/`.)

---

### `frontend/src/App.test.jsx` (modify)

**Analog:** itself, lines 1-163 (inline `useWebSocket` copy to delete) + lines 167-308 (test assertions to keep unchanged — they test observable behavior, not implementation, per RESEARCH.md's Code Examples section).

**Change:** Replace lines 40-163 (`MockWebSocket` stays; inline `useWebSocket` function body goes) with:
```javascript
import { useWebSocket } from '../hooks/useWebSocket'
```
Add one new test asserting `App.jsx` renders `<ChatPane />` (not the old inline `ChatPanel`) per the Phase Requirements → Test Map in RESEARCH.md — no existing analog for this specific assertion; use React Testing Library `render` + `screen.queryByText`/component-presence query, consistent with `@testing-library/react` already imported at the top of this file.

---

### `frontend/pages/index.tsx` (delete)

**No analog needed — deletion only.** Confirmed dead: references `LivePanel`, a component that does not exist anywhere in the repo (verified via read — the file is only 16 lines, self-contained, no other file imports from `pages/`).

---

### `frontend/package.json` (config fix)

**Analog:** `frontend/package-lock.json`'s `packages[""]` block — read directly, values below are the verified real dependency tree the live app already uses:

```json
{
  "name": "optimus-prime-ui",
  "version": "2.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "start": "vite preview",
    "test": "vitest run"
  },
  "dependencies": {
    "lucide-react": "^0.383.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.9.1",
    "@testing-library/react": "^16.3.2",
    "@testing-library/user-event": "^14.6.1",
    "@types/react": "^18.3.1",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.1",
    "@vitest/coverage-v8": "^4.1.3",
    "autoprefixer": "^10.4.20",
    "jsdom": "^29.0.2",
    "postcss": "^8.4.47",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.4.0",
    "vite": "^5.4.10",
    "vitest": "^4.1.3"
  }
}
```
Note: `typescript` is not in the lockfile's `devDependencies` block (only `@types/react`/`@types/react-dom` are) but IS needed per RESEARCH.md's Standard Stack table for `ChatPane.tsx` type-checking — add it explicitly; Vite/esbuild strips types regardless, so this is a dev-time nicety, not a build blocker either way.
**Do not** add `next`, `socket.io-client`, `zustand`, or `@types/node` — see RESEARCH.md's "To Remove" table for rationale on each.
**Checkpoint:** RESEARCH.md flags `vitest` as a slopcheck false-positive (name-similarity to `vite`) — the planner should insert one lightweight `checkpoint:human-verify` before the `npm install` task per RESEARCH.md's Package Legitimacy Audit note, purely for audit-trail purposes, not because it's actually risky.

After this fix: `cd frontend && npm install` (no `npm ci` — lockfile will regenerate to match), then commit the regenerated `package-lock.json`.

---

### `frontend/vite.config.js` (minor edit)

**Analog:** itself, lines 21-25 (the dead `/chat` proxy entry to remove — `/ws/chat` is already covered by the existing `/ws` prefix rule at lines 16-20, `ws: true`). No other changes needed; this file's structure otherwise stays exactly as-is (REST proxies for `/health`, `/directives`, `/scope`, `/gate`, `/report`, `/terminal` all remain, even though several target non-existent backend routes — that is a pre-existing, out-of-scope condition per RESEARCH.md Pitfall 5, not something this phase fixes).

## Shared Patterns

### Panel shape convention
**Source:** every panel in `frontend/src/App.jsx` (StatusBar, ScopePanel, DirectivesPanel, TerminalPanel, FindingsPanel, AgentTracker, PlanPanel, HealthPanel — 8 independent confirmations of the same shape)
**Apply to:** every extracted component file
```jsx
<div className="panel flex flex-col h-full">
  <div className="panel-header">{/* icon + label-xs + optional right-aligned meta */}</div>
  {/* content, typically overflow-y-auto flex-1 */}
</div>
```

### REST fetch + try/catch + loading/error state
**Source:** `App.jsx` `handleSetScope` (1412-1426), `TerminalInput.handleSubmit` (544-567), `FindingsPanel.downloadReport` (691-717), `App.jsx` `fetchHealth` (1243-1248)
**Apply to:** any new panel making a backend call
```jsx
const [busy, setBusy] = useState(false)
const [error, setError] = useState(null)
const doAction = async () => {
  setBusy(true); setError(null)
  try {
    const r = await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) })
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${r.status}`) }
    // success path
  } catch (e) { setError(e.message || String(e)) }
  finally { setBusy(false) }
}
```

### WebSocket connection (reconnect/backoff/heartbeat)
**Source:** `frontend/hooks/useWebSocket.js` (post-extraction; currently `App.jsx` lines 66-184)
**Apply to:** `ChatPane.tsx`'s chat socket, and `App.jsx`'s events (`/ws`) and terminal (`/ws/terminal`) sockets — all three call sites use the identical hook signature `useWebSocket(url, onMessage, enabled?)`.

### Error boundary wrapping
**Source:** `frontend/components/ErrorBoundary.jsx` (new, see Pattern Assignments above)
**Apply to:** every one of the 9 extracted panel components in `App.jsx`'s render tree (D-05 — no exceptions).

### Auth token attachment (new cross-cutting concern, D-11)
**Source:** none in repo yet — net-new, backend-contract-driven (`backend/auth.py` `verify_ws_token`, `backend/config.py` `bearer_token` default `"dev-token"`)
**Apply to:** any WS URL construction (`ChatPane.tsx`'s socket at minimum; consider whether the events/terminal sockets in `App.jsx` should also append `?token=` even though their backend routes don't exist yet — doing so now avoids a second pass later)
```javascript
const token = import.meta.env.VITE_BEARER_TOKEN || 'dev-token'
const url = `${WS_BASE}/ws/chat?token=${encodeURIComponent(token)}`
```

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `frontend/components/ErrorBoundary.jsx` | component (class) | event-driven | No error boundary exists anywhere in the current codebase — first one in the project. Use RESEARCH.md Pattern 1 + `04-UI-SPEC.md`'s locked fallback markup verbatim; both already fully specify the file. |
| `frontend/context/SessionContext.jsx` | provider | pub-sub | No React Context usage exists anywhere in the current codebase — first one in the project. Use RESEARCH.md Pattern 2 verbatim. |
| `frontend/components/ChatPane.tsx` message-router logic (the `data.type` vs `chunk`/`done` vs `event_type` branching specifically — not the file as a whole) | component | streaming | No existing frontend code demultiplexes multiple payload shapes on one socket; `App.jsx`'s `handleChatMessage` (1347-1377) and `handleEventMessage` (1266-1344) are two *separate* handlers on two *separate* sockets today. This is the one place in the phase requiring net-new logic design, not extraction — use RESEARCH.md Pattern 3 verbatim (already verified against backend source). |

## Metadata

**Analog search scope:** `frontend/` (all `.jsx`/`.tsx`/`.js` source and test files), `backend/api/ws_handler.py`, `backend/auth.py`, `backend/config.py` (read-only, contract reference — not modified by this phase), `.planning/phases/04-frontend-split/04-UI-SPEC.md` (locked visual/copy contract), `frontend/package-lock.json` (dependency source of truth)
**Files scanned:** `frontend/src/App.jsx` (1505 lines, full read), `frontend/src/App.test.jsx` (308 lines, full read), `frontend/components/ChatPane.tsx` (154 lines, full read), `frontend/pages/index.tsx` (16 lines, full read), `frontend/vite.config.js` (34 lines, full read), `frontend/package.json` (21 lines, full read), `frontend/src/main.jsx`, `frontend/src/test-setup.js`, `backend/api/ws_handler.py`, `backend/auth.py`, `backend/config.py` — 11 files total, no directory left unexamined for this phase's scope
**Pattern extraction date:** 2026-09-04
