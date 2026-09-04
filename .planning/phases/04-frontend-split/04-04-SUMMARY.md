---
phase: 04-frontend-split
plan: 04
subsystem: frontend
tags: [react, websocket, chat, tdd, protocol-fix]

# Dependency graph
requires: [04-01, 04-02]
provides:
  - "frontend/components/ChatPane.tsx — real, working chat interface: /ws/chat + token auth, init/session handshake, 3-shape message router, onSessionChange/onConnectionChange parent-report callbacks"
  - "frontend/components/ChatMessage.jsx — extracted presentational chat message renderer"
affects: [04-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "WebSocket message routing by key-presence (data.type vs 'chunk'/'done' vs data.event_type), not a single type switch"
    - "Parent-report callback contract: child owns socket/localStorage, optional-chained onX callbacks mirror state upward without becoming the source of truth"

key-files:
  created:
    - frontend/components/ChatMessage.jsx
    - frontend/components/ChatPane.test.tsx
  modified:
    - frontend/components/ChatPane.tsx

key-decisions:
  - "ChatPane sends {type:'init', session_id} via a useEffect watching useWebSocket's connected boolean (false->true transition) rather than a raw ws.onopen handler, since the shared hook owns onopen internally (and already sends its own {type:'reconnect', last_seq} frame there) — ChatPane cannot attach a second onopen, so it reacts to the exposed connected flag instead"
  - "PHASE_FAILED and GATE_PENDING Clawhip events both render using ChatMessage's existing type:'error' (red bubble) styling rather than introducing a new 'system' message type — D-12 asked for 'system/error-style' rendering and the codebase only has an isError branch today, so reusing it avoids adding UI surface not specified in 04-UI-SPEC.md"
  - "Guarded the one-time handshake-error message with a ref that resets on the next successful {type:'session'} ack (not a permanent one-shot) — matches the locked copy's own wording ('Retrying automatically') and the acceptance criterion 'not per WebSocket retry cycle' without suppressing a genuinely new failure after a prior successful connection"
  - "Fixed bottomRef.current?.scrollIntoView({...}) to bottomRef.current?.scrollIntoView?.({...}) — jsdom's test environment does not implement scrollIntoView, and the unguarded call crashed every test via a passive-effect exception (Rule 1 auto-fix, not in original plan text but required for the component to render in any jsdom-based environment)"

patterns-established:
  - "TDD plan-level gate for chat-protocol components: write MockWebSocket-based RED test first (behaviors as `it()` blocks, one per protocol concern), confirm RED via import/resolution failure or assertion failure, then GREEN by full rewrite"

requirements-completed: [UI-01]

# Metrics
duration: 28min
completed: 2026-09-04
---

# Phase 04 Plan 04: Rewrite ChatPane.tsx (Real Chat Interface) Summary

**Rewrote `ChatPane.tsx` from dead Next.js/Socket.IO code into a working raw-WebSocket chat client that connects to the real `/ws/chat` backend route with bearer-token auth, completes the init/session handshake before enabling input, and correctly demultiplexes the three payload shapes (control frames, chat-stream chunks, Clawhip lifecycle events) that arrive on that one socket — closing the WS-auth spoofing threat and fixing three previously-undiagnosed integration bugs simultaneously.**

## Performance

- **Duration:** 28 min
- **Started:** 2026-09-04T17:40:00Z (approx)
- **Completed:** 2026-09-04T18:08:44Z
- **Tasks:** 2
- **Files modified:** 3 (2 created, 1 rewritten)

## Accomplishments

- `frontend/components/ChatMessage.jsx` extracted verbatim from `App.jsx` lines 1129-1179: `isUser`/`isError`/`isPlan` bubble-styling branches preserved exactly, no `dangerouslySetInnerHTML`, default export `ChatMessage({ msg })`
- `frontend/components/ChatPane.tsx` fully rewritten: connects to `ws://${host}/ws/chat?token=${VITE_BEARER_TOKEN||'dev-token'}` via the shared `useWebSocket` hook (no re-implemented reconnect logic), sends `{type:'init', session_id}` on socket open, gates its "connected" UI state on the `{type:'session'}` ack (not raw socket-open), and routes `handleSocketMessage` in the exact order the plan specifies: `data.type` control frames → `'chunk' in data || 'done' in data` stream fragments → `data.event_type` Clawhip lifecycle events, with a no-op default for unrecognized event types
- `onSessionChange`/`onConnectionChange` optional-chained parent-report callbacks implemented: fire on `{type:'session'}` ack (`onSessionChange(session_id)` once, `onConnectionChange(true)`) and on disconnect after a prior ack (`onConnectionChange(false)`) — both safe to omit entirely
- Full feature parity ported from the old inline `ChatPanel` (App.jsx 1015-1128): gate confirm/skip pill buttons, directive hint chips (`$recon`/`$pentest`/`$cloud-audit`/`$scope-discover`), message list via `ChatMessage`, token/model footer, connected/disconnected header states matching 04-UI-SPEC exactly
- `frontend/components/ChatPane.test.tsx` written test-first (9 tests covering behaviors 1-7 plus two edge-case variants for `init`'s null-session-id path and callback-omission safety), confirmed RED against the old Socket.IO file, then GREEN against the rewrite
- T-04-WS-AUTH (Spoofing) threat closed: the `?token=` query param is now appended and asserted present by Test 1
- T-04-04b (DoS via misrender/crash on unexpected `event_type`) mitigated: Test 5 asserts `PHASE_STARTED` (an unhandled event type) neither throws nor adds a chat bubble

## Task Commits

Each task was committed atomically (Task 2 followed the TDD RED→GREEN gate sequence):

1. **Task 1: Extract ChatMessage.jsx (verbatim presentational extraction)** - `6927879` (feat)
2. **Task 2 RED: Add failing ChatPane.test.tsx (behaviors 1-7)** - `36b7c0b` (test)
3. **Task 2 GREEN: Rewrite ChatPane.tsx to pass the tests** - `2c79170` (feat)

## Files Created/Modified

- `frontend/components/ChatMessage.jsx` - New. Default-exports `ChatMessage({ msg })`, verbatim extraction from `App.jsx`
- `frontend/components/ChatPane.test.tsx` - New. 9 tests (MockWebSocket + fake timers + flushPromises pattern reused from `App.test.jsx`) covering URL/auth, init handshake, session-ack gating, chunk accumulation, Clawhip event routing, one-time handshake-error copy, and parent callbacks
- `frontend/components/ChatPane.tsx` - Rewritten. Was 154-line Next.js/Socket.IO dead code; now a raw-WebSocket component using the shared `useWebSocket` hook, correct `/ws/chat` URL + token auth, 3-shape message router, and `onSessionChange`/`onConnectionChange` callback props

## Decisions Made

- Sent the `{type:'init', ...}` handshake frame from a `useEffect` reacting to `useWebSocket`'s `connected` boolean transitioning `false→true`, rather than attaching a second `ws.onopen` — the shared hook already owns `onopen` (and sends its own `{type:'reconnect', last_seq}` frame there per its existing StrictMode-safe reconnect design); ChatPane must not re-implement or override that, per D-09/RESEARCH.md's "Don't Hand-Roll" guidance
- Rendered both `PHASE_FAILED` and `GATE_PENDING` Clawhip events using `ChatMessage`'s existing `type:'error'` (red bubble) styling rather than adding a new "system" message variant — D-12 calls for "system/error-style" rendering and 04-UI-SPEC.md does not define a distinct system-message visual, so reusing the already-locked error styling avoids introducing unspecified UI
- Guarded the handshake-failure system message with a ref (`handshakeErrorShownRef`) that resets on the next successful `{type:'session'}` ack rather than firing only once ever — satisfies "not per WebSocket retry cycle" while still allowing the message to reappear if a *later*, independent handshake failure occurs after a working session
- Fixed `bottomRef.current?.scrollIntoView({...})` → `bottomRef.current?.scrollIntoView?.({...})` (Rule 1 auto-fix): jsdom (used by Vitest's test environment) does not implement `Element.scrollIntoView`, so the unguarded call threw inside a passive effect and crashed every render during testing; the extra optional-chain call guard is a no-op in real browsers where `scrollIntoView` exists

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Guarded `scrollIntoView` call against jsdom's missing implementation**
- **Found during:** Task 2 (first GREEN test run)
- **Issue:** `bottomRef.current?.scrollIntoView({ behavior: 'smooth' })` threw `TypeError: bottomRef.current?.scrollIntoView is not a function` inside a `useEffect`, because jsdom (the test environment) does not implement `Element.scrollIntoView`. This crashed every test that rendered `<ChatPane>` at all, not just ones exercising the scroll behavior.
- **Fix:** Changed to `bottomRef.current?.scrollIntoView?.({ behavior: 'smooth' })` — an additional optional-chain on the method itself, so the call is skipped when the method doesn't exist (jsdom) and behaves identically in real browsers where it does.
- **Files modified:** `frontend/components/ChatPane.tsx`
- **Commit:** `2c79170` (part of the Task 2 GREEN commit, not separately committed)

## Issues Encountered

None beyond the auto-fixed jsdom `scrollIntoView` gap above.

## User Setup Required

None — no external service configuration required. `npm install` was run in this worktree's `frontend/` to populate `node_modules` (already fixed `package.json`/`package-lock.json` from an earlier plan; this is a normal per-worktree setup step, not a plan deviation).

## Next Phase Readiness

- `ChatPane.tsx` is ready to be imported and rendered by `App.jsx` in 04-07, replacing the old inline `ChatPanel`
- `onSessionChange`/`onConnectionChange` props are the tested contract 04-07/UI-03's `SessionContext` mirroring depends on — `App.jsx` can pass `onSessionChange={setSessionId}` / `onConnectionChange={setChatConnected}` directly
- `ChatMessage.jsx` is available for reuse by any other future chat-adjacent surface
- No blockers identified for 04-07

---
*Phase: 04-frontend-split*
*Completed: 2026-09-04*

## Self-Check: PASSED

- FOUND: frontend/components/ChatMessage.jsx
- FOUND: frontend/components/ChatPane.tsx
- FOUND: frontend/components/ChatPane.test.tsx
- FOUND: .planning/phases/04-frontend-split/04-04-SUMMARY.md
- FOUND commit: 6927879 (Task 1)
- FOUND commit: 36b7c0b (Task 2 RED)
- FOUND commit: 2c79170 (Task 2 GREEN)
- FOUND: npx vitest run components/ChatPane.test.tsx components/ChatMessage.jsx — 9/9 passed
- FOUND: npx vitest run (full suite) — 25/25 passed
