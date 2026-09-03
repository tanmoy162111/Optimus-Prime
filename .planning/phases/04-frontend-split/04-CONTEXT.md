# Phase 4: Frontend Split - Context

**Gathered:** 2026-09-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Componentize the React frontend: `ChatPane.tsx` becomes the real, working chat interface rendered by `App.jsx`; `TerminalPanel`, `FindingsPanel`, and `ScopePanel` are extracted into standalone, fault-isolated files under `frontend/components/`; session state (session ID, connection status, engagement metadata) flows through a `SessionContext` instead of prop-drilling. Report generation, tool execution, and backend orchestration are unchanged — this phase is frontend-only.

</domain>

<decisions>
## Implementation Decisions

### Chat interface (D-01, D-02)
- **D-01:** Rewrite `frontend/components/ChatPane.tsx` in place — drop `socket.io-client` and Next.js `style jsx` (no Socket.IO server exists in this backend; `python-socketio[client]` in `backend/requirements.txt` is an outbound client extra only, not a server). Implement the raw `WebSocket` protocol against **`/ws/chat`** directly — **correction (RESEARCH.md):** the real path is `/ws/chat` (`backend/app.py` mounts `ws_handler.router` under `prefix="/ws"`; the handler itself is `@router.websocket("/chat")`), not `/chat`. `frontend/vite.config.js`'s separate `/chat` proxy entry is dead/wrong and should be removed — use the existing `/ws` proxy prefix, the same pattern already used for the events and terminal sockets.
- **D-02:** Fix the broken chat handshake as part of this rewrite. `backend/api/ws_handler.py`'s `/chat` endpoint (mounted at `/ws/chat`, since commit `7f9efad`) requires `{"type":"init", session_id}` → server replies `{"type":"session", session_id}` → only then does `{"type":"chat", "message": ...}` get processed by the orchestrator. The current inline `ChatPanel` in `App.jsx` never sends a `type` field at all, so `msg_type` matches nothing and chat has been silently non-functional via the browser. Port over full feature parity from the current working inline `ChatPanel` (plan display, gate confirm/skip buttons, directive hint chips, token/model footer) while fixing the protocol.
- **D-11 (new, from RESEARCH.md):** WS auth is completely unwired today — `backend/auth.py`'s `verify_ws_token()` requires a `?token=<bearer_token>` query param (default `"dev-token"` from `backend/config.py`) and rejects connections without it before `welcome` is ever sent; no frontend code sends this on any socket today. The rewritten `ChatPane.tsx` (and the extracted events/terminal sockets, via the shared `useWebSocket` hook) must append `?token=<value>` to the WS URL. Read the value from a Vite env var (`import.meta.env.VITE_BEARER_TOKEN`), defaulting to `"dev-token"` in code so it matches the backend's own default with zero required `.env`/`docker-compose.yml` changes — an operator who sets a custom `BEARER_TOKEN` in the backend `.env` sets the matching `VITE_BEARER_TOKEN` for the frontend.
- **D-12 (new, from RESEARCH.md):** The chat WebSocket carries three distinct message shapes on one connection, not just the `type`-keyed control frames D-02 describes: chat-stream fragments (`{chunk, done}` — no `type` key at all) and Clawhip lifecycle events (`{event_type: "PHASE_FAILED"|"GATE_PENDING"|...}`, emitted via `Clawhip.emit()` → the same per-session `manager.send()` as chat). The rewritten `ChatPane.tsx`'s message handler must branch on shape, not assume `data.type` is always present: `chunk`/`done` keys → streaming assistant text; `event_type` key → render as an inline system/error-style message (reuse the error-message styling from `04-UI-SPEC.md`) for `PHASE_FAILED`/`GATE_PENDING`, no-op for other event types (full event handling belongs to the separate, currently-nonexistent events panel, not chat); anything else with a `type` key → the existing `welcome`/`session`/`error`/`pong` control-frame handling from D-02.
- **D-03:** Session init is automatic and silent — on WebSocket open, immediately send `{type: "init", session_id: <from localStorage if present, else null>}`; store the server's returned `session_id` (localStorage + SessionContext) for reconnect/refresh continuity. No "Start Session" UI — single operator, should just work.

### Extraction scope (D-04, D-05)
- **D-04:** Full componentization — extract every inline sub-component currently defined in `App.jsx` into its own file under `frontend/components/`, not just the 3 ROADMAP-named ones: `StatusBar`, `ScopePanel`, `DirectivesPanel`, `TerminalPanel` (+ its `TerminalLine`/`TerminalInput` sub-parts), `FindingsPanel`, `AgentTracker`, `PlanPanel`, `ChatMessage`, `HealthPanel`. `ChatPane.tsx` replaces the current inline `ChatPanel`.
- **D-05:** Every extracted panel gets wrapped in an error boundary (not just the 3 ROADMAP-named panels) — consistent fault isolation across the whole dashboard grid.
- **D-06:** New extracted panel files stay `.jsx`, matching the existing `App.jsx`/`main.jsx` convention. `ChatPane.tsx` remains the sole TypeScript file — its `.tsx` extension is what the requirement specifically names, not a signal to convert the rest of the frontend.

### SessionContext (D-07, D-08, D-09)
- **D-07:** `SessionContext` is broader than the literal ROADMAP wording — it holds session ID, per-socket connection status (`chatConnected`, `eventsConnected`, `terminalConnected` — preserving StatusBar's existing three-way breakdown), plus engagement metadata: `scope`, `currentPlan`, `engagementActive`, `engagementStart`.
- **D-08:** `App.jsx` keeps its own `useState` hooks for these fields as the actual state; `SessionContext.Provider` mirrors/passes the same values down. This is a deliberate smaller-diff choice over making context the single source of truth — accept that `App.jsx` state and context conceptually represent the same values, mirrored rather than unified.
- **D-09:** The generic `useWebSocket` hook (currently duplicated between `App.jsx` and `App.test.jsx`) is extracted into `frontend/hooks/useWebSocket.js` as a shared module. `ChatPane.tsx`, the terminal socket, and the events socket all import this one implementation instead of each maintaining their own copy.

### Next.js remnant cleanup (D-10)
- **D-10:** Delete `frontend/pages/index.tsx` (dead Next.js-era code — references a `LivePanel` component that doesn't exist anywhere in the repo, and is unreachable since the live app is served via Vite's `index.html` → `main.jsx`, not Next.js routing). **Escalated per RESEARCH.md — this is a blocking fix, not just cosmetic:** `frontend/package.json`'s `dependencies` (`next`, `socket.io-client`, `zustand` — the last confirmed unused with zero imports anywhere) and `frontend/package-lock.json` (verified live: `npm ci` fails with `EUSAGE`; the lockfile's own `name` field is `"optimus-prime-ui"`, a different project than `package.json`'s `"optimus-frontend"`) belong to an entirely different Next.js/Socket.IO toolchain. `frontend/Dockerfile` runs `npm install`, which would silently regenerate the lockfile and could drop `vite`, `vitest`, `@vitejs/plugin-react`, `@testing-library/react`, `lucide-react`, or `tailwindcss` from the resolved tree — breaking the actual live app. Fix `package.json` scripts (`dev`/`build`/`start` → Vite equivalents), remove `next`/`socket.io-client`/`zustand` from `dependencies`, add the packages actually imported by the live code (`lucide-react`, `vite`, `@vitejs/plugin-react`, `vitest`, `@testing-library/react` — cross-check against actual imports, don't just trust this list), delete `package-lock.json`, and regenerate it with `npm install` so it matches the real dependency tree.

### Claude's Discretion
- Exact error boundary implementation (class component vs a small shared `ErrorBoundary.jsx` used by all panels — no existing error boundary in the codebase to follow).
- Whether `terminal/exec` (used by `TerminalInput`) becomes session-scoped — the backend endpoint doesn't currently accept a `session_id`, and wiring that through is backend scope; leave the REST call as-is unless it's trivial to pass `session_id` as an additional field the backend can ignore for now.
- Layout/grid CSS structure when panels move to separate files (preserve the current 3-column layout unless a file split makes a cleaner structure obvious).
- Whether the REST `/api/chat` fallback path (`backend/api/chat_routes.py`) needs any frontend usage in this phase — no existing UI code path calls it today; not required to wire it up unless useful as a fallback for `ChatPane.tsx`.

</decisions>

<specifics>
## Specific Ideas

- Chat handshake must exactly match `backend/api/ws_handler.py`'s existing protocol (`welcome` → `init`/`session` → `chat`/`chunk`/`done` → `ping`/`pong`) — this is a fixed, already-implemented backend contract; the frontend fix conforms to it, not the other way around.
- The rewritten `ChatPane.tsx` should not regress any feature the current inline `ChatPanel` already has (plan card, gate confirm/skip, directive hint chips, token/model metadata footer) — treat that inline implementation in `frontend/src/App.jsx` (function `ChatPanel`, and `ChatMessage`) as the feature reference to port from.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` §UI-01/UI-02/UI-03 — the three locked requirements this phase satisfies
- `.planning/ROADMAP.md` Phase 4 section — goal, success criteria, dependency on Phase 3
- `.planning/PROJECT.md` §Active — Milestone 3 bullet list (Wire ChatPane.tsx, extract panels, error boundaries, SessionProvider)

### Backend chat contract (frontend must conform to this, not change it)
- `backend/api/ws_handler.py` — the `/chat` WebSocket handler: `welcome`/`init`/`session`/`chat`/`chunk`/`done`/`ping`/`pong` message types, and the `msg_type` dispatch that silently no-ops on unrecognized/missing `type`
- `backend/api/chat_routes.py` — the REST `/api/chat` fallback (`ChatRequest`/`ChatResponse` shape), for reference only, not required to be wired up this phase

### Existing frontend code to reuse/replace
- `frontend/src/App.jsx` — current monolith; the `useWebSocket` hook (lines ~66-184) to extract; `ChatPanel`/`ChatMessage` (lines ~1015-1179) as the feature-parity reference for the ChatPane.tsx rewrite; `ScopePanel`/`TerminalPanel`/`FindingsPanel` and all other inline sub-components to extract
- `frontend/components/ChatPane.tsx` — file to rewrite in place (currently Next.js/Socket.IO, incompatible with the live stack)
- `frontend/pages/index.tsx` — dead code to delete (references nonexistent `LivePanel`)
- `frontend/package.json` — scripts to fix (currently `next dev`/`next build`/`next start`, should be Vite equivalents)
- `frontend/vite.config.js` — the live dev-server proxy config (`/health`, `/directives`, `/scope`, `/gate`, `/report`, `/terminal`, `/ws`, `/chat`) — any new socket/fetch code must go through these same proxied paths
- `frontend/src/App.test.jsx` — existing test harness with an inline duplicate of `useWebSocket`; extracting the hook to `frontend/hooks/useWebSocket.js` should let this test import the real implementation instead of maintaining its own copy (there's a `TODO(Task 3): Delete this inline copy after App.jsx is updated` comment already there)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `useWebSocket` hook in `App.jsx` (lines ~66-184) — health-check gate, exponential backoff, heartbeat, visibility-change reconnect, sequence tracking — solid, reusable as-is once extracted to its own module
- Existing Tailwind utility classes (`panel`, `panel-header`, `label-xs`, `input-field`, `btn-primary`, `btn-ghost`, `dot-live`) already used consistently across all panels — carry these over to extracted files unchanged
- `ChatPanel`/`ChatMessage` functions in `App.jsx` — full working chat UI (minus the protocol bug) to use as the feature-parity source when rewriting `ChatPane.tsx`

### Established Patterns
- Every panel follows the same shape: `<div className="panel flex flex-col h-full"><div className="panel-header">...</div>{content}</div>` — keep this convention in extracted files
- WebSocket connections are all raw browser `WebSocket`, proxied through Vite's `server.proxy` config in dev (`ws: true` entries) — no Socket.IO anywhere in the live stack
- `EVENT_ICONS`, `SEVERITY_MAP`, `REPORT_FORMATS_UI`, `REPORT_FRAMEWORKS` constants and `fmtTime`/`fmtElapsed`/`renderPayload` utility functions in `App.jsx` are shared across multiple panels being extracted — these need a shared home (e.g. `frontend/lib/constants.js`, `frontend/lib/format.js`) rather than being duplicated per file

### Integration Points
- `App.jsx`'s three WebSocket connections (`/ws` events, `/chat`, `/ws/terminal`) each currently own their `connected` state locally via separate `useWebSocket(...)` calls — after this phase, `chatConnected`/`eventsConnected`/`terminalConnected` flow into `SessionContext` for consumption by `StatusBar` and any other component, while the socket instances/hooks themselves can still live wherever makes sense (e.g. `ChatPane.tsx` owns its own chat socket via the shared hook)
- `handleSetScope`, `handleGateResolve`, `handleSendMessage`/`handleSendDirective` remain in `App.jsx` and get passed as callbacks/context values to extracted panels, since they call backend REST endpoints (`/scope`, `/gate/{action}/{id}`) and the chat socket's `send`

</code_context>

<deferred>
## Deferred Ideas

- Converting the rest of the frontend to TypeScript — out of scope; only `ChatPane.tsx` stays `.tsx` per D-06
- Making SessionContext the single source of truth (replacing `App.jsx`'s `useState` hooks outright) — deferred per D-08; App.jsx keeps owning state, context mirrors it
- Wiring `terminal/exec` to be session-scoped on the backend — backend change, out of scope for this frontend-only phase
- Using the REST `/api/chat` fallback from the frontend — no current UI path needs it; not required this phase

</deferred>

---

*Phase: 04-frontend-split*
*Context gathered: 2026-09-02*
