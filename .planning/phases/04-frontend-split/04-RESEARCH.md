# Phase 4: Frontend Split - Research

**Researched:** 2026-09-04
**Domain:** React (Vite) frontend componentization, raw WebSocket protocol integration, React error boundaries, React Context
**Confidence:** HIGH (all critical findings verified directly against source files and live `npm`/`slopcheck` runs in this repo, not training-data guesses)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Chat interface (D-01, D-02)**
- **D-01:** Rewrite `frontend/components/ChatPane.tsx` in place — drop `socket.io-client` and Next.js `style jsx` (no Socket.IO server exists in this backend; `python-socketio[client]` in `backend/requirements.txt` is an outbound client extra only, not a server). Implement the raw `WebSocket` protocol against `/chat` directly.
- **D-02:** Fix the broken chat handshake as part of this rewrite. `backend/api/ws_handler.py`'s `/chat` endpoint (since commit `7f9efad`) requires `{"type":"init", session_id}` → server replies `{"type":"session", session_id}` → only then does `{"type":"chat", "message": ...}` get processed by the orchestrator. The current inline `ChatPanel` in `App.jsx` never sends a `type` field at all, so `msg_type` matches nothing and chat has been silently non-functional via the browser. Port over full feature parity from the current working inline `ChatPanel` (plan display, gate confirm/skip buttons, directive hint chips, token/model footer) while fixing the protocol.
- **D-03:** Session init is automatic and silent — on WebSocket open, immediately send `{type: "init", session_id: <from localStorage if present, else null>}`; store the server's returned `session_id` (localStorage + SessionContext) for reconnect/refresh continuity. No "Start Session" UI — single operator, should just work.

**Extraction scope (D-04, D-05)**
- **D-04:** Full componentization — extract every inline sub-component currently defined in `App.jsx` into its own file under `frontend/components/`, not just the 3 ROADMAP-named ones: `StatusBar`, `ScopePanel`, `DirectivesPanel`, `TerminalPanel` (+ its `TerminalLine`/`TerminalInput` sub-parts), `FindingsPanel`, `AgentTracker`, `PlanPanel`, `ChatMessage`, `HealthPanel`. `ChatPane.tsx` replaces the current inline `ChatPanel`.
- **D-05:** Every extracted panel gets wrapped in an error boundary (not just the 3 ROADMAP-named panels) — consistent fault isolation across the whole dashboard grid.
- **D-06:** New extracted panel files stay `.jsx`, matching the existing `App.jsx`/`main.jsx` convention. `ChatPane.tsx` remains the sole TypeScript file — its `.tsx` extension is what the requirement specifically names, not a signal to convert the rest of the frontend.

**SessionContext (D-07, D-08, D-09)**
- **D-07:** `SessionContext` is broader than the literal ROADMAP wording — it holds session ID, per-socket connection status (`chatConnected`, `eventsConnected`, `terminalConnected` — preserving StatusBar's existing three-way breakdown), plus engagement metadata: `scope`, `currentPlan`, `engagementActive`, `engagementStart`.
- **D-08:** `App.jsx` keeps its own `useState` hooks for these fields as the actual state; `SessionContext.Provider` mirrors/passes the same values down. This is a deliberate smaller-diff choice over making context the single source of truth — accept that `App.jsx` state and context conceptually represent the same values, mirrored rather than unified.
- **D-09:** The generic `useWebSocket` hook (currently duplicated between `App.jsx` and `App.test.jsx`) is extracted into `frontend/hooks/useWebSocket.js` as a shared module. `ChatPane.tsx`, the terminal socket, and the events socket all import this one implementation instead of each maintaining their own copy.

**Next.js remnant cleanup (D-10)**
- **D-10:** Delete `frontend/pages/index.tsx` (dead Next.js-era code — references a `LivePanel` component that doesn't exist anywhere in the repo, and is unreachable since the live app is served via Vite's `index.html` → `main.jsx`, not Next.js routing). Fix `frontend/package.json` scripts (`dev`/`build`/`start`) to reflect the actual Vite toolchain instead of `next dev`/`next build`/`next start`.

### Claude's Discretion
- Exact error boundary implementation (class component vs a small shared `ErrorBoundary.jsx` used by all panels — no existing error boundary in the codebase to follow).
- Whether `terminal/exec` (used by `TerminalInput`) becomes session-scoped — the backend endpoint doesn't currently accept a `session_id`, and wiring that through is backend scope; leave the REST call as-is unless it's trivial to pass `session_id` as an additional field the backend can ignore for now.
- Layout/grid CSS structure when panels move to separate files (preserve the current 3-column layout unless a file split makes a cleaner structure obvious).
- Whether the REST `/api/chat` fallback path (`backend/api/chat_routes.py`) needs any frontend usage in this phase — no existing UI code path calls it today; not required to wire it up unless useful as a fallback for `ChatPane.tsx`.

### Deferred Ideas (OUT OF SCOPE)
- Converting the rest of the frontend to TypeScript — out of scope; only `ChatPane.tsx` stays `.tsx` per D-06.
- Making SessionContext the single source of truth (replacing `App.jsx`'s `useState` hooks outright) — deferred per D-08; App.jsx keeps owning state, context mirrors it.
- Wiring `terminal/exec` to be session-scoped on the backend — backend change, out of scope for this frontend-only phase.
- Using the REST `/api/chat` fallback from the frontend — no current UI path needs it; not required this phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| UI-01 | `ChatPane.tsx` is imported and rendered in `App.jsx` as the primary chat interface | Correct WS URL/path (`/ws/chat`, not `/chat`), auth token requirement, and 3-way message-shape multiplexing documented in Common Pitfalls and Code Examples below — required for the rewritten `ChatPane.tsx` to actually connect and function, not just structurally exist |
| UI-02 | `TerminalPanel`, `FindingsPanel`, and `ScopePanel` extracted into separate files, each wrapped in an error boundary | React 18 class-component error boundary pattern + reusable `ErrorBoundary.jsx` documented in Architecture Patterns / Code Examples; exact fallback markup already locked in UI-SPEC |
| UI-03 | `SessionProvider` context introduced, replacing prop-drilling | Context + `useMemo` mirroring pattern (D-08) documented in Architecture Patterns |
</phase_requirements>

## Summary

This phase's technical risk is almost entirely in **protocol correctness**, not React mechanics. The React-side work (extracting ~9 already-styled components, writing one error-boundary class component, introducing one context provider) is mechanical and low-risk. The genuinely hard part — and the part CONTEXT.md's summary of the backend protocol does not fully capture — is that the current frontend has **three separate, independently-broken integration bugs**, only one of which (missing `type` field) is named in D-02. Verified directly against `backend/api/ws_handler.py`, `backend/app.py`, and `backend/agent/clawhip.py`:

1. **Wrong URL.** `ws_handler.router` is mounted at `app.include_router(ws_handler.router, prefix="/ws")` in `backend/app.py`, and the handler itself is `@router.websocket("/chat")`. The real, live path is **`/ws/chat`**, not `/chat`. The current frontend connects to `${WS_BASE}/chat`, and `vite.config.js` proxies `/chat` to `ws://backend:8000` — a path with no matching backend route. `/ws/chat` is *already* covered by the existing `/ws` proxy prefix rule (`ws: true`), so no `vite.config.js` change is required — only the frontend's connection URL needs to change to `${WS_BASE}/ws/chat`.
2. **Missing auth token.** `backend/auth.py`'s `verify_ws_token()` requires a `?token=<bearer_token>` query parameter matching `settings.bearer_token` (default `"dev-token"`, no `.env` override present in this repo). No existing frontend code sends this token on any of the three WebSocket connections. Without it, `websocket.accept()` still completes the browser-side handshake (so `onopen` fires) but the server closes immediately after with code 1008 — before ever sending `welcome`. The existing backoff/retry logic handles this uniformly (as a generic disconnect), but the handshake will *never* succeed until the frontend sends the token.
3. **Three multiplexed message shapes on one socket, not one.** The chat socket delivers three structurally different payload shapes that must be told apart by key presence, not a single `type` field as CONTEXT.md's summary implies:
   - Control frames: `{"type": "welcome"|"session"|"error"|"pong", ...}`
   - Chat stream fragments: `{"chunk": "...", "done": false|true}` — **no `type` key at all**
   - Clawhip lifecycle/audit events: `{"event_type": "PHASE_STARTED"|"PHASE_COMPLETED"|"PHASE_FAILED"|"PLAN_REJECTED"|"GATE_PENDING", "directive_id", "detail", "error"}` — delivered via `Clawhip.emit()` → `ws_handler.manager.send(session_id, ...)`, i.e. **the same per-session connection ChatPane owns**, not a separate events stream.

Beyond the protocol, there is a **separate, unrelated, already-verified-broken build issue**: `frontend/package.json` and `frontend/package-lock.json` are for two different projects. `package.json` declares Next.js/Socket.IO/Zustand (`optimus-frontend` 1.0.0); `package-lock.json` is already the real Vite/Vitest/Testing-Library/lucide-react/Tailwind toolchain the live code actually uses (`optimus-prime-ui` 2.0.0). Running `npm ci` in this repo **fails immediately** (`EUSAGE`, verified live). Running `npm install` — what `frontend/Dockerfile` actually calls — "succeeds" but silently regenerates `package-lock.json` to match the *wrong* `package.json`, which would delete `vite`/`vitest`/`lucide-react`/`tailwindcss` from the resolved tree entirely and break the app outright. D-10 as literally scoped ("fix scripts") does not cover this; the fix must extend to the full `dependencies`/`devDependencies` block.

Finally, verified directly: `frontend/node_modules` does not exist in this environment, and none of `/scope`, `/gate/{action}/{id}`, `/directives`, `/report/{format}`, `/terminal/exec`, or a bare `/ws` (events) or `/ws/terminal` route exist anywhere in the current backend (confirmed by exhaustive grep for `APIRouter`/`@router.`/`@app.`/`include_router` across all of `backend/`). Every non-chat panel being extracted in this phase (`ScopePanel`, `DirectivesPanel`, `TerminalPanel`, `FindingsPanel`, gate confirm/skip) already calls into 404ing or connection-refused endpoints today. This is **pre-existing, out-of-scope backend absence**, not a regression the extraction introduces — the correct action is to preserve these calls structurally (extraction is a refactor, not a backend fix) while documenting clearly that their non-functional appearance after extraction is expected, not a bug in the plan's execution.

**Primary recommendation:** Fix `package.json`'s dependency block (source of truth: the existing, already-correct `package-lock.json`) before writing any component code, so `npm install`/tests actually run; build `ChatPane.tsx` against `${WS_BASE}/ws/chat` with a `?token=` query param and a message router that switches on `type` vs. `chunk`/`done` vs. `event_type`, not a single `type` dispatch; hand-roll one small class-based `ErrorBoundary.jsx` (React only supports error boundaries as classes — no hook equivalent exists, library or not) and wrap every extracted panel in it per the UI-SPEC fallback markup verbatim; introduce `SessionContext` as a thin, `useMemo`-wrapped mirror of `App.jsx`'s existing `useState` values per D-08, with zero change to who owns state.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Chat WebSocket handshake/session lifecycle | Browser / Client | API / Backend (contract owner — `ws_handler.py` is fixed, frontend conforms) | Raw browser `WebSocket` API, connection state lives in `ChatPane.tsx`; protocol shape is dictated by the backend and must not be altered |
| Panel rendering (Terminal/Findings/Scope/etc.) | Browser / Client | — | Pure presentational React components, no server-side rendering (Next.js SSR already removed/dead per D-10) |
| Error boundary / fault isolation | Browser / Client | — | React error boundaries are a client-runtime-only mechanism (class component lifecycle methods); no backend involvement |
| Session state distribution (SessionContext) | Browser / Client | — | In-memory React Context, mirrors `App.jsx` `useState` (D-08); no persistence beyond `localStorage` for `session_id` |
| Auth token attachment | Browser / Client | API / Backend (verifies via `verify_ws_token`) | Frontend must attach `?token=`; backend rejects connections without a match — currently neither side is wired for this in the live code path |
| Report download / scope config / gate resolve / terminal exec | Browser / Client | API / Backend (currently absent — 404/refused) | REST calls originate client-side; the backend routes they target do not exist in the current system, unchanged by this phase |
| Build toolchain (Vite/Vitest/Tailwind) | Browser / Client (build tool, not runtime) | — | Dev-time only; affects whether the app can be built/tested at all, not a runtime architectural tier, but blocking for all of the above if broken |

## Standard Stack

### Core (already present, keep as-is)
| Library | Version (pinned in lockfile) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| react / react-dom | ^18.3.1 | UI runtime | Already the project's chosen version; matches CLAUDE.md tech stack (React 18.3.0) |
| vite | ^5.4.10 (resolved 5.4.21) | Dev server + bundler | Already configured (`vite.config.js`), already proxies backend correctly for REST + WS; no reason to introduce Next.js patterns |
| lucide-react | ^0.383.0 | Icon set | Already used throughout `App.jsx`; UI-SPEC locks this as the icon library, no new icons in this phase |
| typescript | ^5.4.0 | Type-checking for `ChatPane.tsx` only | D-06 keeps `.tsx` scoped to this one file; esbuild (via Vite) strips types without a separate `tsc` gate, so no build-blocking risk from lacking a `tsconfig.json`, but adding a minimal one is good practice |

### Supporting (already resolved in package-lock.json, but MISSING from package.json — must be added)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| vitest | ^4.1.3 | Test runner | Already the framework `App.test.jsx` and `vite.config.js`'s `test` block assume |
| @vitejs/plugin-react | ^4.3.1 | JSX/Fast Refresh for Vite | Already imported in `vite.config.js`; handles both `.jsx` and `.tsx` |
| @testing-library/react | ^16.3.2 | Component/hook testing | Already imported in `App.test.jsx` (`renderHook`, `act`) |
| @testing-library/jest-dom | ^6.9.1 | DOM matchers | Already imported in `frontend/src/test-setup.js` |
| @testing-library/user-event | ^14.6.1 | User-interaction simulation in tests | Not yet used, but already resolved in lockfile — available for new panel/ErrorBoundary tests |
| jsdom | ^29.0.2 | Test DOM environment | Required by `vite.config.js`'s `test.environment: 'jsdom'` |
| tailwindcss / postcss / autoprefixer | ^3.4.14 / ^8.4.47 / ^10.4.20 | Styling pipeline | Already configured via `tailwind.config.js` / `postcss.config.js`; every extracted panel must keep using these utility classes verbatim per UI-SPEC |
| @vitest/coverage-v8 | ^4.1.3 | Coverage reporting | Already resolved in lockfile; optional to wire a `coverage` script but no harm including it since it's already fetched |

### To Remove from package.json (dead/unused)
| Package | Why Remove |
|---------|-----------|
| `next` | Dead — Next.js is not the live stack; `index.html`/`main.jsx`/Vite serve the app. `frontend/pages/index.tsx` (the only Next.js page) is deleted in this phase per D-10. |
| `socket.io-client` | Dead — D-01 replaces the Socket.IO client in `ChatPane.tsx` with raw `WebSocket`; no Socket.IO server exists anywhere in `backend/`. |
| `zustand` | Dead — **not present in `package-lock.json` at all** (confirmed: it was never actually installed), not imported anywhere in the codebase (`grep` across `frontend/` finds zero usages). CLAUDE.md's dependency list mentions it as a "key dependency," but the code and lockfile both contradict that — it is unused. D-08 keeps `App.jsx` `useState` as the source of truth, so there is no reason to add real zustand usage in this phase either. |
| `@types/node` | Next.js-era leftover (used for `NEXT_PUBLIC_*` / server-side type support); not needed for a pure Vite CSR app unless a config file needs Node typings — safe to drop unless a later task needs it for `vite.config.js` typing (low risk either way). |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled `ErrorBoundary.jsx` class component | `react-error-boundary` (npm, v6.1.4 latest, `npm view` confirmed) | Library adds a `useErrorBoundary`/`ErrorBoundary` API sugar over the same class-based mechanism (React still requires a class under the hood — no hook-only error boundary exists in React 18). For ~9 panels needing one identical fallback (UI-SPEC already locks the exact markup), a ~30-line hand-rolled class component avoids a new dependency in an already dependency-lean project and matches the codebase's existing minimal-deps style. Recommend hand-rolled. |
| Raw `WebSocket` + manual handshake state machine | A WS client library (e.g. `reconnecting-websocket`, `socket.io-client`) | D-01 explicitly mandates raw `WebSocket` — no Socket.IO server exists. The existing `useWebSocket` hook already implements reconnect/backoff/heartbeat correctly; no library needed, would only add scope. |
| `useMemo`-wrapped Context value | A state library (Zustand, Jotai, Redux) | D-08 explicitly keeps `App.jsx` `useState` as the state owner (mirrored, not unified) — introducing a state library would contradict this locked decision and add a currently-unused dependency back in. |

**Installation (fix `frontend/package.json`, then run):**
```bash
cd frontend && npm install
```
No new packages need fetching from the registry — every package above is already resolved with real integrity hashes in the current `package-lock.json`. The fix is to declaration-align `package.json`'s `dependencies`/`devDependencies` (and `name`/`version`, currently `optimus-frontend`/`1.0.0` vs. the lockfile's `optimus-prime-ui`/`2.0.0`) so `npm install`/`npm ci` stop conflicting with the already-correct lockfile.

**Version verification:** Verified live in this repo — `npm ci` fails with `EUSAGE` today (package.json/package-lock.json out of sync); `npm install --dry-run` "succeeds" but would only add Next.js/Socket.IO/Zustand packages, confirming the lockfile's Vite/Vitest/Testing-Library toolchain would be silently dropped if `npm install` were run against the current `package.json` unmodified. `npm view <pkg> version` confirms current registry latest versions (vite 8.2.2, vitest 5.0.0, lucide-react 1.40.0, tailwindcss 4.3.3, @vitejs/plugin-react 6.1.1, @testing-library/react 16.3.3) are all newer than the pinned lockfile versions — **do not bump to these latest majors in this phase**; attempting to install vitest 5 + vite 8 + @vitest/coverage-v8 5 together in this sandbox produced a real `ERESOLVE` peer-dependency conflict (verified), whereas the already-pinned lockfile versions (vite 5.4.x / vitest 4.1.3 / @vitejs/plugin-react 4.x) are already mutually compatible and already resolved. Keep the existing pinned versions; this phase is a componentization refactor, not a dependency upgrade.

## Package Legitimacy Audit

> All packages below are already present in `frontend/package-lock.json` with real npm registry integrity hashes — they are not new installs, but `slopcheck` was still run per protocol against the exact proposed `package.json` dependency set (in an isolated scratch directory, since running it in-place hits the pre-existing `package.json`/lockfile conflict described above and produces unrelated `ERESOLVE` errors, not legitimacy verdicts).

| Package | Registry | Age/Downloads (well-known) | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-------------|-----------|-------------|
| react / react-dom | npm | Meta, multi-year, billions/wk | facebook/react | OK | Approved (already in use) |
| lucide-react | npm | established, millions/wk | lucide-icons/lucide | OK | Approved (already in use) |
| vite | npm | established, tens of millions/wk | vitejs/vite | OK | Approved (already in use) |
| @vitejs/plugin-react | npm | official Vite org package | vitejs/vite-plugin-react | OK | Approved (already in use) |
| @testing-library/react | npm | established, millions/wk | testing-library/react-testing-library | OK | Approved (already in use) |
| @testing-library/jest-dom | npm | established | testing-library/jest-dom | OK | Approved (already in use) |
| @testing-library/user-event | npm | established | testing-library/user-event | OK | Approved (not yet used, available) |
| jsdom | npm | established, very high downloads | jsdom/jsdom | OK | Approved (already in use) |
| tailwindcss | npm | established, tens of millions/wk | tailwindlabs/tailwindcss | OK | Approved (already in use) |
| postcss / autoprefixer | npm | established, foundational tooling | postcss/postcss, postcss/autoprefixer | OK | Approved (already in use) |
| typescript | npm | Microsoft, established | microsoft/TypeScript | OK | Approved (already in use) |
| @vitest/coverage-v8 | npm | official Vitest org package | vitest-dev/vitest | OK | Approved |
| **vitest** | npm | established, official Vite-ecosystem test runner, tens of millions/wk | vitest-dev/vitest | **SUS** — `slopcheck` flags it as "suspiciously close to 'vite' — could be a typosquat" | **Flagged (false positive)** — see note below |

**Note on the `vitest` [SUS] flag:** This is a heuristic false positive. `vitest` is the official Vite-ecosystem test runner (vitest.dev, `vitest-dev/vitest` on GitHub), already present with a real integrity hash in this repo's own `package-lock.json`, already imported by name throughout `frontend/src/App.test.jsx` and `frontend/vite.config.js`'s `test` config block, and its name similarity to `vite` is because it is Vite's own test runner by design, not because it impersonates it. Per protocol, keep it but the planner should still add a lightweight `checkpoint:human-verify` before the `npm install` task purely to satisfy the audit trail — expect it to be a fast "confirm and continue," not a real blocker.

**Packages removed due to slopcheck [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** `vitest` (false positive, see note above — planner adds one lightweight checkpoint before install).

## Architecture Patterns

### System Architecture Diagram

```
Browser
  │
  ├─ main.jsx → App.jsx (state owner: session_id, scope, currentPlan,
  │   engagementActive/Start, chatConnected/eventsConnected/terminalConnected)
  │       │
  │       ├─ <SessionContext.Provider value={useMemo(...)}>
  │       │     │
  │       │     ├─ <StatusBar />            (reads context: connection dots)
  │       │     ├─ <ErrorBoundary><ScopePanel /></ErrorBoundary>
  │       │     ├─ <ErrorBoundary><DirectivesPanel /></ErrorBoundary>
  │       │     ├─ <ErrorBoundary><ChatPane /></ErrorBoundary>   ← owns its own WS
  │       │     ├─ <ErrorBoundary><TerminalPanel /></ErrorBoundary>
  │       │     ├─ <ErrorBoundary><PlanPanel /></ErrorBoundary>
  │       │     ├─ <ErrorBoundary><AgentTracker /></ErrorBoundary>
  │       │     ├─ <ErrorBoundary><FindingsPanel /></ErrorBoundary>
  │       │     └─ <ErrorBoundary><HealthPanel /></ErrorBoundary>
  │       │
  │       └─ owns 3x useWebSocket(url, onMessage) calls:
  │             /ws/chat      (real backend route — ChatPane's socket)
  │             /ws           (events — NO backend route exists; always fails/retries)
  │             /ws/terminal  (NO backend route exists; always fails/retries)
  │
  └─ REST calls (fetch): /health (real), /scope /gate/* /directives /report/* /terminal/exec
        (NONE of these exist server-side except /health — pre-existing, out of scope)

Backend (FastAPI, unchanged by this phase)
  app.py
   ├─ include_router(chat_routes.router, prefix="/api")   → POST /api/chat (REST, unused by frontend)
   │                                                          GET  /api/session/{id}
   │                                                          GET  /api/health (duplicate of below)
   ├─ include_router(ws_handler.router, prefix="/ws")     → WS   /ws/chat  ← the ONLY real socket
   │        └─ verify_ws_token() requires ?token=<bearer_token>
   │        └─ manager.send(session_id, payload) delivers BOTH:
   │              - {chunk, done} chat stream fragments (from orchestrator.process_stream)
   │              - {event_type, directive_id, detail, error} Clawhip lifecycle events
   │            → both arrive on the SAME socket ChatPane owns
   └─ GET /health (top-level, real, used by useWebSocket's health-gate)
```

### Recommended Project Structure
```
frontend/
├── components/
│   ├── ChatPane.tsx          # rewritten: raw WS, handshake, feature parity (D-01/02/03)
│   ├── ChatMessage.jsx       # extracted from App.jsx
│   ├── StatusBar.jsx
│   ├── ScopePanel.jsx
│   ├── DirectivesPanel.jsx
│   ├── TerminalPanel.jsx     # + TerminalLine.jsx, TerminalInput.jsx (or co-located)
│   ├── FindingsPanel.jsx
│   ├── AgentTracker.jsx
│   ├── PlanPanel.jsx
│   ├── HealthPanel.jsx
│   └── ErrorBoundary.jsx     # new, shared by every panel above (D-05)
├── context/
│   └── SessionContext.jsx    # new (D-07/08) — createContext + Provider mirror pattern
├── hooks/
│   └── useWebSocket.js       # extracted (D-09), used by ChatPane + events + terminal sockets
├── lib/
│   ├── constants.js          # EVENT_ICONS, SEVERITY_MAP, REPORT_FORMATS_UI, REPORT_FRAMEWORKS
│   └── format.js             # fmtTime, fmtElapsed, renderPayload
├── src/
│   ├── App.jsx                # slimmed: state + composition only, imports from components/
│   ├── App.test.jsx           # updated to import the real hooks/useWebSocket.js
│   ├── index.css
│   ├── main.jsx
│   └── test-setup.js
├── pages/                     # DELETED entirely (D-10 — index.tsx was the only file)
└── package.json                # dependencies/devDependencies fixed to match package-lock.json
```

### Pattern 1: ErrorBoundary (class component, hand-rolled)
**What:** React error boundaries can only be implemented via class components (`static getDerivedStateFromError` / `componentDidCatch`) — there is no hook-based equivalent in React 18. `react-error-boundary` (npm, evaluated above) wraps the exact same mechanism; not adopting it avoids a new dependency for a single, simple, already-specified fallback.
**When to use:** Wrap every extracted panel individually (D-05) so one panel's render crash doesn't unmount the whole grid.
**Example (fallback markup and copy locked verbatim by UI-SPEC):**
```jsx
// frontend/components/ErrorBoundary.jsx
// Source: React error boundary API is documented at https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary
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
    // Bump resetKey so the boundary's children are actually re-mounted
    // (fresh instance), not merely re-rendered with hasError cleared.
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
Usage: `<ErrorBoundary panelName="Terminal"><TerminalPanel {...props} /></ErrorBoundary>`

### Pattern 2: SessionContext mirror (D-08)
**What:** `App.jsx` keeps owning `useState`; a `useMemo`d value object is handed to the Provider so consumers don't re-render on every unrelated `App.jsx` render.
**When to use:** Any value that changes at a different cadence than every render (session id, connection flags, scope, plan) — which is all of D-07's fields.
**Example:**
```jsx
// frontend/context/SessionContext.jsx
// Source: React docs — https://react.dev/reference/react/useContext
// and https://react.dev/learn/passing-data-deeply-with-context#step-3-provide-the-context
import { createContext, useContext } from 'react'

export const SessionContext = createContext(null)
export const useSession = () => useContext(SessionContext)
```
```jsx
// frontend/src/App.jsx (excerpt)
const sessionValue = useMemo(() => ({
  sessionId, chatConnected, eventsConnected, terminalConnected,
  scope, currentPlan, engagementActive, engagementStart,
}), [sessionId, chatConnected, eventsConnected, terminalConnected,
     scope, currentPlan, engagementActive, engagementStart])

return (
  <SessionContext.Provider value={sessionValue}>
    {/* ...grid... */}
  </SessionContext.Provider>
)
```
**Pitfall avoided:** passing `value={{ sessionId, ... }}` inline (a new object literal every render) defeats `useMemo`'s purpose and re-renders every consumer on every `App.jsx` render tick, even unrelated ones (e.g. a terminal line arriving). The `useMemo` dependency array must list every mirrored field individually.

### Pattern 3: ChatPane message router (three shapes, one socket)
**What:** Distinguish control frames, chat-stream fragments, and Clawhip lifecycle events by key presence, not a single `type` switch.
**Example:**
```typescript
// frontend/components/ChatPane.tsx (excerpt)
// Source: verified directly against backend/api/ws_handler.py and backend/agent/clawhip.py in this repo
function handleSocketMessage(data: any) {
  if (data.type) {
    // control frame: welcome | session | error | pong
    switch (data.type) {
      case 'session':
        onSessionAck(data.session_id)
        break
      case 'error':
        onHandshakeError(data.message)
        break
      // 'welcome' / 'pong' — no UI action needed
    }
    return
  }
  if ('chunk' in data || 'done' in data) {
    // chat stream fragment — no type field
    appendChunk(data.chunk, data.done)
    return
  }
  if (data.event_type) {
    // Clawhip lifecycle/audit event, arrives on this same socket
    // (PHASE_STARTED/PHASE_COMPLETED/PHASE_FAILED/PLAN_REJECTED/GATE_PENDING)
    // Minimum-safe handling: ignore gracefully (matches today's behavior where
    // these are unreachable). See Open Questions for the optional richer path.
  }
}
```

### Anti-Patterns to Avoid
- **Assuming `/chat` is the live path:** it is not; `/ws/chat` is. Copy-pasting CONTEXT.md's prose literally without checking `app.py`'s `include_router(..., prefix="/ws")` reproduces the exact bug being fixed.
- **Treating chat-stream fragments as having a `type` field:** `manager.send(session_id, {"chunk": chunk, "done": False})` has no `type` key. A `switch(data.type)` that falls through to a default case for chunks will silently misroute them.
- **New Context object literal per render:** always `useMemo` the Provider `value`.
- **Re-implementing error boundary as a function component with try/catch:** does not work for render-phase errors in child components — React error boundaries are class-only.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Error boundary mechanism | A custom `try/catch` wrapper in a function component | React's class-based `getDerivedStateFromError`/`componentDidCatch` (Pattern 1 above) | Function components cannot catch render-phase errors in their children by design — this is a hard React limitation, not a style choice |
| WebSocket reconnect/backoff/heartbeat | A new reconnect implementation for `ChatPane`'s socket | The existing `useWebSocket` hook (already handles health-gate, exponential backoff, heartbeat, visibility-change reconnect, StrictMode-safe via `mountedRef`) — extract it to `frontend/hooks/useWebSocket.js` per D-09 and reuse for all three sockets | It already correctly solves double-invoke-under-StrictMode, which is easy to get wrong when rewritten from scratch |
| Test double for `WebSocket` | A new mock per test file | The existing `MockWebSocket` class pattern in `App.test.jsx` (readyState constants, `_open()`/`_message()`/`_error()` helpers) | Already proven against the exact hook being extracted; reuse to avoid divergence between test doubles |

**Key insight:** Every piece of "hard" infrastructure needed for this phase (reconnect logic, a WS test harness) already exists correctly in the codebase — the actual net-new code is small (one ErrorBoundary class, one Context module, corrected URLs/message routing in ChatPane).

## Common Pitfalls

### Pitfall 1: `package.json`/`package-lock.json` are for two different projects
**What goes wrong:** `npm ci` fails outright (`EUSAGE`, verified live in this repo); `npm install` "succeeds" but regenerates the lockfile to match `package.json`'s Next.js/Socket.IO/Zustand set, silently dropping `vite`/`vitest`/`@testing-library/react`/`lucide-react`/`tailwindcss` from the resolved tree.
**Why it happens:** `package.json` was never updated when the project migrated from Next.js to Vite; only `package-lock.json` (and the actual source files) reflect the migration.
**How to avoid:** Rewrite `package.json`'s `name`, `version`, `dependencies`, and `devDependencies` to match `package-lock.json`'s `packages[""]` block (values given in the Standard Stack table above) as an early task in this phase, before any other frontend work depends on `npm install` succeeding correctly.
**Warning signs:** `npm ci` erroring with `EUSAGE`; `lucide-react` import errors; `vitest`/`@testing-library/react` "module not found" when running tests.

### Pitfall 2: Wrong chat WebSocket path
**What goes wrong:** Connecting to `${WS_BASE}/chat` (current code, and what CONTEXT.md's prose literally says) will never succeed — the backend has no route there. The real, mounted route is `/ws/chat`.
**Why it happens:** `backend/app.py` mounts `ws_handler.router` with `prefix="/ws"`, and the handler is itself declared as `@router.websocket("/chat")` — the combination is easy to miss without reading `app.py` directly.
**How to avoid:** Connect to `${WS_BASE}/ws/chat`. No `vite.config.js` change needed — the existing `/ws` proxy prefix (`ws: true`) already covers `/ws/chat`. The `/chat` proxy entry in `vite.config.js` now proxies to a nonexistent backend path and should be removed or left as inert dead config (not blocking, but confusing if left).
**Warning signs:** WebSocket connects (browser `onopen` may or may not even fire, depending on whether Vite's dev proxy 404s the upgrade) but no `welcome`/`session` message is ever received.

### Pitfall 3: Missing WS auth token
**What goes wrong:** `verify_ws_token()` requires `?token=<bearer_token>` (default `"dev-token"`, no `.env` override in this repo). No current frontend code sends it. Even after fixing the URL, every connection attempt will be closed by the server (code 1008) immediately after opening, before `welcome` is sent.
**Why it happens:** The token requirement was added to the backend (Phase 2/3 security work) without a corresponding frontend update — this predates Phase 4.
**How to avoid:** Append `?token=<value>` to the WS URL. Given "personal use, single operator, static bearer token" (CLAUDE.md constraint), the simplest correct approach is a `VITE_BEARER_TOKEN` env var (Vite exposes `VITE_`-prefixed vars via `import.meta.env`) with a fallback default matching the backend's default (`"dev-token"`) for local dev. Note `docker-compose.yml`'s frontend `environment:` block currently sets `NEXT_PUBLIC_API_URL`/`NEXT_PUBLIC_WS_URL` — Next.js-era vars Vite does not read; if the planner wires a real token env var, it likely needs a matching `docker-compose.yml` update (outside `frontend/`, worth flagging even though this phase is scoped frontend-only, since docker-compose is deployment glue, not application code).
**Warning signs:** Chat socket opens then immediately closes with code 1008; server logs show no `welcome` sent.

### Pitfall 4: Treating the chat socket as single-purpose
**What goes wrong:** `Clawhip.emit()` (backend/agent/clawhip.py) delivers `PHASE_STARTED`/`PHASE_COMPLETED`/`PHASE_FAILED`/`PLAN_REJECTED`/`GATE_PENDING` events via the *same* `manager.send(session_id, ...)` call used for chat chunks — i.e., on the exact socket `ChatPane` owns, not a separate `/ws` events stream (which does not exist). A message handler written assuming "this socket only ever carries `{chunk, done}` or `{type: ...}`" will either crash on `event_type`-shaped payloads or silently mis-render them as chat content.
**Why it happens:** The old (pre-cleanup) architecture had a genuinely separate events stream; the current backend collapsed lifecycle-event delivery onto the per-session chat connection during Phase 3's ORCH-01 work, but no frontend code was updated to match.
**How to avoid:** Route on key presence as shown in Pattern 3 above; at minimum, gracefully ignore `event_type`-shaped messages (matches today's de facto behavior of dropping unrecognized shapes) rather than let them fall through to chat-content rendering logic.
**Warning signs:** Malformed/blank chat bubbles appearing when a `PHASE_FAILED` or `GATE_PENDING` event fires server-side.

### Pitfall 5: Extracted panels "still look broken" — this is expected, not a regression
**What goes wrong:** After extracting `ScopePanel`/`DirectivesPanel`/`TerminalPanel`/`FindingsPanel`/gate buttons into their own files, they will still fail to fetch `/scope`, `/directives`, `/terminal/exec`, `/report/*`, `/gate/{action}/{id}` — none of these routes exist in the current backend (verified: exhaustive grep of `backend/` for every route-registration pattern found only `/health`, `/api/chat`, `/api/session/{id}`, `/api/health`, and `WS /ws/chat`). The events (`/ws`) and terminal (`/ws/terminal`) sockets will also never connect.
**Why it happens:** These backend endpoints were part of the old, pre-Phase-1 system deleted under CLEAN-01 and were never rebuilt in the new `backend/agent/` architecture — this predates Phase 4 entirely.
**How to avoid:** Do not attempt to build or stub these backend routes in this phase — it is explicitly out of scope (frontend-only phase, no requirement covers it). Extract the panels exactly as they behave today (fetch calls preserved verbatim); document this clearly so a plan-checker or the operator doesn't mistake "TerminalPanel shows no live output" as a regression introduced by the split.
**Warning signs:** None at execution time — this is a pre-existing, already-present condition, not something a test would newly catch. Flag it in the plan's verification notes instead.

### Pitfall 6: React 18 StrictMode double-invoking effects
**What goes wrong:** In development, React 18 `<StrictMode>` (already wrapping `<App />` in `main.jsx`) mounts, unmounts, and remounts every component once to surface effect-cleanup bugs — a naive WebSocket-in-`useEffect` will open two sockets.
**Why it happens:** Intentional React 18 dev-mode behavior to catch missing cleanup.
**How to avoid:** The existing `useWebSocket` hook already guards this correctly via `mountedRef` (set `true` on effect run, checked before creating the socket, set `false` in cleanup) — preserve this exact guard unchanged when extracting to `frontend/hooks/useWebSocket.js`; do not "simplify" it away.
**Warning signs:** Two `WebSocket` connections opening per mount in dev tools' Network tab (does not manifest in production builds without StrictMode).

## Code Examples

### Extracting the hook without behavior drift
```javascript
// frontend/hooks/useWebSocket.js
// Source: direct extraction of the existing, working implementation in
// frontend/src/App.jsx lines ~66-184 — no behavioral changes, only relocation.
// (Full body omitted here — see App.jsx for the canonical implementation to move verbatim.)
```
The one behavioral trap when extracting: `App.test.jsx` currently has an *inline copy* (lines 47-163) with a `TODO(Task 3): Delete this inline copy after App.jsx is updated` comment already in place. After extraction, `App.test.jsx` should `import { useWebSocket } from '../hooks/useWebSocket'` (adjusting `global.WebSocket = MockWebSocket` as it already does) and delete the inline copy — the test assertions themselves (`toEqual({ type: 'reconnect', last_seq: 0 })`, heartbeat timing, backoff timing) should not need to change since they test observable behavior, not implementation.

### Panel extraction shape (preserve verbatim)
```jsx
// Every extracted panel keeps this exact shape (already established convention):
export default function ScopePanel({ scope, onSetScope }) {
  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">{/* ... */}</div>
      {/* content */}
    </div>
  )
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Next.js pages router + Socket.IO client (`frontend/pages/index.tsx`, `ChatPane.tsx`'s current `socket.io-client` usage) | Vite CSR + raw `WebSocket` (`vite.config.js`, `App.jsx`, `index.html` → `main.jsx`) | Migration already happened for everything except `ChatPane.tsx`/`pages/index.tsx`/`package.json` | This phase completes a migration that was already ~90% done elsewhere in the repo — it is not introducing a new architecture, it is finishing one already in progress |
| Separate events (`/ws`) + terminal (`/ws/terminal`) streams (implied by `App.jsx`'s current 3-socket design) | Single per-session chat connection carrying both chat chunks and Clawhip lifecycle events | Phase 3 (ORCH-01/clawhip work, completed 2026-09-02) | Frontend code (including CONTEXT.md's own protocol description) has not caught up to this backend consolidation |

**Deprecated/outdated:**
- `socket.io-client`/`style jsx` in `ChatPane.tsx`: no server-side counterpart exists; replaced by D-01.
- `NEXT_PUBLIC_API_URL`/`NEXT_PUBLIC_WS_URL` in `docker-compose.yml`'s frontend service: Next.js-only env var convention, not read by Vite (`import.meta.env` only sees `VITE_`-prefixed vars) and not referenced anywhere in `App.jsx` (which uses `window.location.host` instead) — effectively dead configuration, flagged as an Open Question below rather than a locked task since `docker-compose.yml` is arguably outside "frontend-only" scope.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The correct fix for the auth-token gap is a `VITE_BEARER_TOKEN` env var with a `"dev-token"` fallback, rather than some other mechanism (e.g. a login screen, or leaving auth unwired and accepting perpetual 1008 closes) | Pitfall 3 / Open Questions | If wrong, the chat handshake will never functionally succeed even after the URL/message-shape fixes, silently undermining UI-01's success criterion despite the code being structurally correct |
| A2 | Removing `next`, `socket.io-client`, and `zustand` from `package.json` (rather than just adding the missing Vite toolchain deps alongside them) is safe | Standard Stack — "To Remove" table | Low risk: `zustand` is unused and not even in the lockfile; `next`/`socket.io-client` are actively replaced by this phase's own decisions (D-01, D-10). If some other undiscovered code path imports them, `npm run build` would fail loudly and immediately — not a silent risk |
| A3 | The `vitest` slopcheck [SUS] flag is a false positive rather than a real supply-chain risk | Package Legitimacy Audit | Very low: verified as the official Vite org's own test runner, already resolved with a real integrity hash in this repo's committed lockfile prior to this session |

**If this table is empty:** N/A — see above.

## Open Questions (RESOLVED)

> All three questions below were answered during `/gsd:discuss-phase` (see 04-CONTEXT.md). Annotations added inline; none remain blocking.

1. **Should ChatPane surface Clawhip lifecycle events (`PHASE_FAILED`, `GATE_PENDING`, etc.) in the chat UI, or only silently ignore them?** — **RESOLVED by D-12:** ChatPane's message router branches on payload shape and renders `PHASE_FAILED`/`GATE_PENDING` as inline system/error-style messages (reusing 04-UI-SPEC error styling), no-ops other `event_type`s, and must not crash/misrender on `event_type`-shaped payloads. Planned in 04-04 Task 2 (behaviors 4-5).
   - What we know: these events already arrive on the socket `ChatPane` owns (verified — `Clawhip.emit()` uses the same `ws_handler.manager.send(session_id, ...)` as chat chunks). Phase 3's own stated goal for ORCH-01 was "the operator sees phase failures surface in the chat UI instead of silent drops" — but no frontend code currently does this.
   - What's unclear: whether rendering these as system messages in `ChatPane` is in scope for Phase 4 (UI-01/02/03 don't explicitly require it) or should be deferred as a follow-up.
   - Recommendation: at minimum, the message router must not crash or misrender on `event_type`-shaped payloads (Pitfall 4). Treat "render them as system messages" as Claude's Discretion / a cheap bonus given the wiring is already 90% forced by this phase's own message-router work, not a hard requirement.

2. **Where does the WS auth token value come from at runtime?** — **RESOLVED by D-11:** hardcoded `'dev-token'` default with an `import.meta.env.VITE_BEARER_TOKEN` override (`import.meta.env.VITE_BEARER_TOKEN || 'dev-token'`), appended as `?token=` to the WS URL — zero required `.env`/`docker-compose.yml` change, matching CLAUDE.md's personal-use static-bearer-token posture. Planned in 04-04 Task 2 (behavior 1).
   - What we know: backend defaults to `"dev-token"`; no `.env` file exists in this repo overriding it; `docker-compose.yml`'s frontend environment block uses dead Next.js-only var names.
   - What's unclear: whether the planner should introduce a `VITE_BEARER_TOKEN` build-time env var (requiring a `docker-compose.yml`/`.env.example` touch, technically outside `frontend/`) or hardcode `"dev-token"` as a personal-use-only default directly in `ChatPane.tsx`/`useWebSocket.js`.
   - Recommendation: given CLAUDE.md's explicit "personal use, no auth hardening beyond static bearer token required for now" constraint, a hardcoded default with an env-var override (`import.meta.env.VITE_BEARER_TOKEN || 'dev-token'`) is proportionate and matches the project's stated security posture — flag for a quick confirm rather than treating as blocked.

3. **Does `docker-compose.yml`'s frontend `environment:` block need updating in this phase?** — **RESOLVED: deferred, non-blocking (RESEARCH.md's own recommendation):** the live app ignores these stale Next.js-only vars entirely (`window.location.host` is used instead), so leaving them does not newly break anything; not in scope for this frontend-only phase.
   - What we know: it currently sets Next.js-only vars Vite never reads.
   - What's unclear: whether "frontend-only" scope (per CONTEXT.md's phase boundary) extends to this repo-root file.
   - Recommendation: treat as adjacent cleanup, low-risk to include alongside the token-wiring task if the planner adds one, but not blocking if deferred — the app already ignores these vars entirely today (`window.location.host` is used instead), so leaving them stale doesn't newly break anything.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js | Frontend build/dev/test | ✓ | (container: node:20-alpine per Dockerfile) | — |
| npm | Package install | ✓ | present in this environment | — |
| `frontend/node_modules` | Running dev server / tests locally (outside Docker) | ✗ | not installed | Run `npm install` after fixing `package.json` (Pitfall 1) — required before any local `npm run dev`/`npm test` in this phase |
| Backend (`/ws/chat`, `/health`) | Chat handshake to actually succeed end-to-end | not verified running in this research session (no live backend process checked) | — | Not blocking for writing/testing the frontend code (Vitest mocks `WebSocket` entirely); blocking only for manual browser verification of UI-01's success criterion |
| slopcheck (Python) | Package Legitimacy Audit | ✓ | 0.6.1, already installed | — |

**Missing dependencies with no fallback:** none blocking for code authorship; `frontend/node_modules` must be installed before any local dev/test run, but this is a normal one-time setup task, not an environmental gap.

**Missing dependencies with fallback:** none beyond the above.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest ^4.1.3 (already configured in `vite.config.js`'s `test` block: `environment: 'jsdom'`, `globals: true`, `setupFiles: ['./src/test-setup.js']`, `passWithNoTests: true`) |
| Config file | `frontend/vite.config.js` (embedded `test` key — no separate `vitest.config.js`) |
| Quick run command | `cd frontend && npx vitest run --reporter=dot` (or add a `"test": "vitest run"` script to `package.json` — currently missing entirely; only `dev`/`build`/`start` scripts exist) |
| Full suite command | `cd frontend && npx vitest run` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|-------------|
| UI-01 | `ChatPane.tsx` sends `{type:"init",...}` on open, transitions to "connected" only after `{type:"session"}` ack, routes `{chunk,done}` vs `{type:...}` vs `{event_type:...}` correctly | unit (mocked `WebSocket`, following the existing `MockWebSocket` pattern) | `npx vitest run frontend/components/ChatPane.test.tsx` | ❌ Wave 0 — new file needed |
| UI-01 | `App.jsx` renders `<ChatPane />` (not the old inline `ChatPanel`) | unit/integration (React Testing Library render + query) | `npx vitest run frontend/src/App.test.jsx` | ⚠️ Partial — `App.test.jsx` exists but currently only tests the inline `useWebSocket` copy, not `App`'s render tree; needs a render-tree assertion added |
| UI-02 | Error boundary catches a thrown error from a panel and renders the locked fallback markup without unmounting siblings | unit (render a panel that throws, assert fallback text + sibling panel still renders) | `npx vitest run frontend/components/ErrorBoundary.test.jsx` | ❌ Wave 0 — new file needed |
| UI-02 | `TerminalPanel`/`FindingsPanel`/`ScopePanel` exist as standalone files, importable independently | unit (import + shallow render smoke test per extracted file) | `npx vitest run frontend/components/*.test.jsx` | ❌ Wave 0 — new files needed (or fold into one `components.smoke.test.jsx`) |
| UI-03 | A component nested under `SessionContext.Provider` reads session state via `useContext(SessionContext)` without prop-drilling | unit (render a test consumer, assert values match Provider input) | `npx vitest run frontend/context/SessionContext.test.jsx` | ❌ Wave 0 — new file needed |
| UI-03 | `SessionContext`'s value is memoized (doesn't create a new object reference on unrelated `App.jsx` re-renders) | unit (render count assertion via a consumer wrapped in `React.memo`/render-spy) | `npx vitest run frontend/context/SessionContext.test.jsx` | ❌ Wave 0 — same file as above |

### Sampling Rate
- **Per task commit:** `npx vitest run <changed-file>.test.jsx` (fast, targeted)
- **Per wave merge:** `npx vitest run` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`, plus a manual browser check of UI-01's React DevTools criterion (automated tests cannot inspect the DevTools component tree)

### Wave 0 Gaps
- [ ] `frontend/package.json` dependency fix (Pitfall 1) — nothing else in this table can run without it
- [ ] `frontend/components/ChatPane.test.tsx` — covers UI-01 handshake/routing behavior
- [ ] `frontend/components/ErrorBoundary.test.jsx` — covers UI-02 fault isolation
- [ ] `frontend/context/SessionContext.test.jsx` — covers UI-03 context access + memoization
- [ ] `"test": "vitest run"` script added to `package.json` — currently absent, needed for a documented quick-run command
- [ ] `App.test.jsx` updated to import the real `hooks/useWebSocket.js` (delete the inline `TODO(Task 3)` copy) and add a render-tree assertion that `ChatPane` (not the old inline `ChatPanel`) is what's rendered

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | Static bearer token (`verify_ws_token`/`verify_token` in `backend/auth.py`, unchanged by this phase) — frontend must attach `?token=` to WS connections for the *existing* backend control to actually take effect (currently it doesn't, per Pitfall 3); this phase does not change the auth mechanism itself, only makes the frontend conform to it |
| V3 Session Management | yes | `session_id` issued by `session_store.create()`/`resolve()`, persisted client-side via `localStorage` per D-03 — standard pattern for a single-operator, no-multi-tenancy app; no new session-fixation risk introduced since the backend already validates/regenerates on `init` |
| V4 Access Control | no | Single operator, no role/permission model in scope (CLAUDE.md: "no auth hardening beyond static bearer token required for now") |
| V5 Input Validation | n/a for this phase | No new user-input surfaces are added; existing `input`/`textarea` fields are unchanged, React's JSX escaping already prevents injection into the DOM for rendered chat/event content |
| V6 Cryptography | no | No cryptographic operations in this phase's scope (token comparison is a plain string equality check in existing backend code, unchanged) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Unauthenticated WebSocket connection (current state — token never sent) | Spoofing | Attach `?token=` per Pitfall 3/Open Question 2; already enforced server-side, just unused client-side today |
| XSS via rendered chat/event content | Tampering / Elevation of Privilege | React's default JSX text-node escaping already covers this (`{msg.content}` inside JSX, not `dangerouslySetInnerHTML`) — verified: no `dangerouslySetInnerHTML` usage exists anywhere in `App.jsx` today; do not introduce it when porting `ChatMessage` |
| Error boundary fallback leaking stack traces to the UI | Information Disclosure | The locked UI-SPEC fallback copy ("This panel crashed" / generic body text) already avoids rendering `error.message`/`error.stack` in the UI — log the actual error via `console.error`/`componentDidCatch` only, never render it into the fallback markup |

## Sources

### Primary (HIGH confidence — verified directly against this repo's source files)
- `backend/api/ws_handler.py` — full `/chat` WebSocket handler read in full: message types, `manager.send` delivery mechanism, auth check placement
- `backend/app.py` — router mounting (`prefix="/ws"`), confirming the real path is `/ws/chat`
- `backend/agent/clawhip.py` — confirmed lifecycle events are delivered via the same `manager.send(session_id, ...)` used for chat, not a separate stream
- `backend/auth.py` — `verify_ws_token()` query-param requirement
- `backend/config.py` — `bearer_token` default value, confirmed no `.env` override present
- `backend/api/chat_routes.py` — REST `/api/chat` fallback shape, confirmed unused by any current frontend code path
- `frontend/package.json` vs. `frontend/package-lock.json` — read and diffed directly; root package name/version and dependency sets confirmed to diverge
- Live `npm ci` run in this repo — confirmed `EUSAGE` failure with full missing-package list
- Live `npm install --dry-run` in this repo — confirmed it would only add Next.js/Socket.IO/Zustand packages
- Live `npm view <pkg> version` for vite, vitest, lucide-react, tailwindcss, @vitejs/plugin-react, @testing-library/react, react-error-boundary — current registry versions
- Live `slopcheck scan` (against current `package.json` and against a scratch `package.json` matching the proposed dependency set) — full legitimacy verdicts, including the `vitest` false-positive flag
- `frontend/src/App.jsx`, `frontend/src/App.test.jsx`, `frontend/components/ChatPane.tsx`, `frontend/pages/index.tsx`, `frontend/vite.config.js`, `frontend/tailwind.config.js`, `frontend/postcss.config.js`, `frontend/src/index.css`, `frontend/src/test-setup.js`, `frontend/src/main.jsx`, `frontend/index.html`, `frontend/Dockerfile` — all read in full
- `docker-compose.yml` (frontend service block), `.env.example` — read for env-var provenance
- Exhaustive `grep` across all of `backend/*.py` for `APIRouter`/`@router.`/`@app.`/`include_router` — confirmed the complete route inventory (only `/health`, `/api/chat`, `/api/session/{id}`, `/api/health`, `WS /ws/chat` exist)

### Secondary (MEDIUM confidence)
- React error boundary reset-via-key-change pattern — cross-referenced against `legacy.reactjs.org/docs/error-boundaries.html` and multiple current tutorials (WebSearch), consistent with training knowledge; React 18/19 have not changed this API surface
- `react-error-boundary` v6.1.4 as current latest — `npm view` confirmed, evaluated only as an alternative, not adopted

### Tertiary (LOW confidence)
- None — every claim material to planning was either verified directly against source in this repo or against a live tool run in this session

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified via live `npm`/`slopcheck` runs against this repo's actual lockfile, not training-data assumptions
- Architecture (protocol/message shapes): HIGH — verified by reading the complete, current backend source (`ws_handler.py`, `app.py`, `clawhip.py`, `auth.py`) rather than trusting CONTEXT.md's prose summary, which was found to be incomplete on two of three integration bugs
- Pitfalls: HIGH — every pitfall in this document reproduces from either a direct source-code read or a live command run in this session; none are speculative

**Research date:** 2026-09-04
**Valid until:** 14 days — this research is tightly coupled to the exact current state of `backend/api/ws_handler.py`, `backend/agent/clawhip.py`, and `frontend/package.json`/`package-lock.json`; any further backend changes to the chat/event protocol or any manual `npm install` run against the current broken `package.json` would invalidate key findings
