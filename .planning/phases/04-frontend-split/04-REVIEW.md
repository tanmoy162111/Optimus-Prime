---
phase: 04-frontend-split
reviewed: 2026-09-04T18:32:41Z
depth: standard
files_reviewed: 26
files_reviewed_list:
  - frontend/components/AgentTracker.jsx
  - frontend/components/ChatMessage.jsx
  - frontend/components/ChatPane.test.tsx
  - frontend/components/ChatPane.tsx
  - frontend/components/DirectivesPanel.jsx
  - frontend/components/ErrorBoundary.jsx
  - frontend/components/ErrorBoundary.test.jsx
  - frontend/components/FindingsPanel.jsx
  - frontend/components/HealthPanel.jsx
  - frontend/components/panels-batch1.smoke.test.jsx
  - frontend/components/panels-batch2.smoke.test.jsx
  - frontend/components/PlanPanel.jsx
  - frontend/components/ScopePanel.jsx
  - frontend/components/StatusBar.jsx
  - frontend/components/TerminalInput.jsx
  - frontend/components/TerminalLine.jsx
  - frontend/components/TerminalPanel.jsx
  - frontend/context/SessionContext.jsx
  - frontend/context/SessionContext.test.jsx
  - frontend/hooks/useWebSocket.js
  - frontend/lib/constants.js
  - frontend/lib/format.js
  - frontend/package.json
  - frontend/package-lock.json
  - frontend/src/App.jsx
  - frontend/src/App.test.jsx
  - frontend/vite.config.js
findings:
  critical: 1
  warning: 4
  info: 4
  total: 9
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-09-04T18:32:41Z
**Depth:** standard
**Files Reviewed:** 26 (unique source files; package.json/package-lock.json/vite.config.js reviewed as config)
**Status:** issues_found

## Summary

Reviewed the frontend-split extraction: `App.jsx` decomposed into `ChatPane`, panel components, `useWebSocket`, `SessionContext`, and `lib/` helpers, with accompanying tests. The extraction itself is faithful (tests assert the exact D-07/D-08/D-12 contracts called out in comments), and the `useWebSocket` reconnect/backoff/heartbeat logic and `ErrorBoundary` fault isolation are solid. No `eval`, `innerHTML`, or `dangerouslySetInnerHTML` usage, no hardcoded API secrets found in application code, no empty catch blocks that swallow errors silently without a documented reason.

However, one **pre-existing dedup bug that survived the split** causes real findings (the app's core data output) to be silently dropped whenever more than one finding lacks a `finding_id` — which the code's own `payload.finding || payload` / `finding.title` fallback shows is an anticipated case, and which the legacy backend `Finding` dataclass (`backend/agent/conversation.py:51-57`) confirms has no `finding_id` field at all. This is classified Critical because it causes silent data loss in a security-findings-tracking tool. There is also a fully non-functional `DirectivesPanel` (clicks produce no user-visible effect) and a hardcoded token fallback that fails silently when misconfigured, plus several smaller dead-code items left over from the pre-split `App.jsx`.

## Critical Issues

### CR-01: Findings (and agents) with no unique ID are silently deduplicated away after the first one

**File:** `frontend/src/App.jsx:76-84` (and the analogous `frontend/src/App.jsx:97-103` for agents)
**Issue:**
```js
if (event_type === 'FINDING_CREATED' && payload) {
  const finding = payload.finding || payload
  if (finding.finding_id || finding.title) {
    setFindings(prev => {
      const exists = prev.some(f => f.finding_id === finding.finding_id)
      return exists ? prev : [...prev, finding]
    })
  }
}
```
The dedup guard `f.finding_id === finding.finding_id` compares `undefined === undefined` whenever a finding has no `finding_id`. The surrounding `if (finding.finding_id || finding.title)` guard explicitly anticipates findings that only have a `title` (no `finding_id`) — and the legacy backend `Finding` dataclass (`backend/agent/conversation.py:51-57`) has no `finding_id` field at all, so this is not a hypothetical: any backend path that emits findings without `finding_id` will hit this. The first such finding is added to `prev`; every subsequent finding without a `finding_id` matches `undefined === undefined` against that first entry and is treated as "already exists," so it is silently discarded. The operator loses real security findings with no error, no log line, and no indication anything was dropped — directly undermining the "reviewing findings, not running commands" core value stated in `CLAUDE.md`.

The same shape of bug exists for `AGENT_SPAWNED` at `App.jsx:97-103` (`a.task_id === payload.task_id`), though it's lower risk in practice since `task_id` is more likely to always be backend-assigned.

**Fix:** Only treat two records as duplicates when they both have a defined identifying key; fall back to always appending when no ID is present (or synthesize a client-side ID):
```js
if (finding.finding_id || finding.title) {
  setFindings(prev => {
    const exists = finding.finding_id != null &&
      prev.some(f => f.finding_id != null && f.finding_id === finding.finding_id)
    return exists ? prev : [...prev, finding]
  })
}
```
Apply the same `!= null` guard to the `AGENT_SPAWNED` dedup check at line 99.

## Warnings

### WR-01: DirectivesPanel is fully rendered and clickable but produces no user-visible effect

**File:** `frontend/src/App.jsx:177-179`, wired to `frontend/components/DirectivesPanel.jsx:29-31`
**Issue:**
```js
const handleSendDirective = useCallback((directive) => {
  console.warn('Directive triggered from DirectivesPanel — use the chat input or its hint chips to send:', directive)
}, [])
```
`DirectivesPanel` renders 8 fully-styled, hover-responsive buttons (`$pentest`, `$recon`, etc.) that visually invite the operator to click them. Clicking any of them does nothing except log a `console.warn` that no operator will ever see during normal use — no toast, no input population, no redirect to chat. This reads to the user as a broken feature rather than an intentional constraint, and the code comment acknowledges it's out of this plan's interface contract rather than a deliberate UX decision.
**Fix:** At minimum, populate the chat input (mirroring `ChatPane`'s own hint-chip behavior) or disable/hide the buttons that aren't wired up so the UI doesn't imply functionality that doesn't exist:
```js
const handleSendDirective = useCallback((directive) => {
  // forward through a shared input-population callback exposed by ChatPane,
  // or visually mark these as "coming soon" if not wired this phase
}, [])
```

### WR-02: Hardcoded fallback bearer token fails silently when env var is unset

**File:** `frontend/components/ChatPane.tsx:45`
**Issue:**
```ts
const token = (import.meta as any).env?.VITE_BEARER_TOKEN || 'dev-token'
```
If `VITE_BEARER_TOKEN` isn't set at build time (e.g., a misconfigured `.env` in a fresh deployment), the app silently connects with the literal string `'dev-token'`. If the backend's actual configured token differs, the WebSocket handshake fails at the auth layer and the operator only ever sees a perpetual "disconnected" state with no indication of *why* — there's no console warning distinguishing "using fallback token" from "backend down."
**Fix:** Warn loudly (and visibly) when falling back:
```ts
const envToken = (import.meta as any).env?.VITE_BEARER_TOKEN
if (!envToken) console.error('VITE_BEARER_TOKEN is not set — chat auth will likely fail')
const token = envToken || 'dev-token'
```

### WR-03: `AGENT_SPAWNED` dedup has the same undefined-collision flaw as CR-01

**File:** `frontend/src/App.jsx:97-103`
**Issue:** See CR-01 — `prev.some(a => a.task_id === payload.task_id)` will drop any second-and-later `AGENT_SPAWNED` event whose `payload.task_id` is `undefined`. Lower likelihood than the findings case since agent spawn events are more likely to always carry a `task_id`, but the same defensive fix should be applied for consistency and to avoid an agent silently vanishing from the tracker.
**Fix:** Same `!= null` guard as CR-01.

### WR-04: Port input silently drops user-typed `0` and non-numeric radix ambiguity

**File:** `frontend/components/ScopePanel.jsx:18`
**Issue:**
```js
ports: ports === 'all' ? 'all' : ports.split(',').map(p => parseInt(p.trim())).filter(Boolean)
```
`parseInt` is called without an explicit radix, and `.filter(Boolean)` drops any parsed value that is falsy — this includes `0` (a technically-invalid-but-user-typed port) as well as `NaN` from garbage input (e.g., a stray comma `"80,,443"` silently drops the empty segment with no feedback that input was malformed).
**Fix:**
```js
ports: ports === 'all' ? 'all' : ports.split(',').map(p => parseInt(p.trim(), 10)).filter(n => Number.isInteger(n) && n > 0)
```

## Info

### IN-01: `events`/`eventCounter` state is computed but never consumed

**File:** `frontend/src/App.jsx:24,32,71,146`
**Issue:** `handleEventMessage` builds an `event` record (with a fresh `Math.random()`-based `_id` each time) and appends it to `events` state on every single WebSocket event, and separately bumps `eventCounter`. Neither `events` nor `eventCounter` is read anywhere else in `App.jsx`, nor passed to any child component. This looks like a leftover from a pre-split event-log panel that either didn't survive the split or was never wired up, and causes two extra state updates/re-renders per event for no observable benefit.
**Fix:** Remove `events`/`setEvents`/`eventCounter`/`setEventCounter` if no event-log UI is planned, or wire them into a panel if one is coming in a later phase.

### IN-02: Dead exports left over from pre-split App.jsx

**File:** `frontend/lib/format.js:1-4,12-32` (`fmtTime`, `renderPayload`), `frontend/lib/constants.js:16-39` (`EVENT_ICONS`)
**Issue:** `fmtTime`, `renderPayload`, and `EVENT_ICONS` are exported but have zero importers anywhere in `frontend/` (verified via repo-wide grep). These appear to be helpers for rendering the same event-log UI implied by IN-01, extracted during the split but never wired to a consumer.
**Fix:** Either delete these exports or wire them up alongside IN-01's fix; carrying unused exports forward makes it harder for the next reader to tell what's load-bearing.

### IN-03: `PlanPanel` phase list key has no fallback for missing/duplicate `phase_id`

**File:** `frontend/components/PlanPanel.jsx:43`
**Issue:** `key={phase.phase_id}` will produce a React key warning (and can cause incorrect reconciliation/animation glitches) if the backend ever emits a phase without a `phase_id`, or two phases share one during a transient plan-update race.
**Fix:** `key={phase.phase_id || i}`.

### IN-04: Zero-token responses hide the token/model footer

**File:** `frontend/components/ChatMessage.jsx:38`
**Issue:** `{msg.metadata?.tokens && (...)}` treats a legitimate `tokens: 0` value as falsy, so a message reporting a genuinely zero-token response silently omits its "tokens · model" footer instead of showing "0 tokens · <model>".
**Fix:** `{msg.metadata?.tokens != null && (...)}`.

---

_Reviewed: 2026-09-04T18:32:41Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
