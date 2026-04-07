# Design: Robust WebSocket Reconnect + Autonomous Scan Monitor

**Date:** 2026-04-08  
**Status:** Approved

---

## Problem

1. **Reconnect failure after PC reboot.** The `useWebSocket` hook retries every 3 s, but the chain silently dies during extended backend downtime (minutes-long reboot). The UI stays stuck on DISCONNECTED. A manual F5 refresh restores connectivity — proving a fresh React mount works, but the retry closure breaks.

2. **No autonomous fix loop during scans.** When an agent or tool fails mid-scan (Python traceback, SSH unreachable, env misconfiguration), there is no mechanism to detect and resolve the issue without operator intervention.

---

## Solution Overview

### Part 1 — Rewrite `useWebSocket` (frontend/src/App.jsx)

Replace the fragile `setTimeout(connect, 3000)` chain with a proper state machine.

#### Preserved existing behavior (no regressions)
- `lastSeq` ref tracking; `{type: 'reconnect', last_seq}` sent on every `onopen`
- `send(data)` return value (true/false)
- `enabled` parameter gates all connection attempts
- All three hook instances unchanged: `/ws`, `/chat`, `/ws/terminal`

#### New behavior

**`mounted` ref**  
Set `true` on mount, `false` on cleanup. Every async callback (`onopen`, `onclose`, `onerror`, timeout, visibility handler) checks `mountedRef.current` before acting. Eliminates stale-closure side-effects after unmount/remount.

**Health-check gate**  
Before opening a WebSocket, `tryConnect()` pings `/health` (up to 3 attempts, 1 s apart). Only proceeds when health returns 200. Prevents "connected but broken" state where Vite accepts the WS upgrade but FastAPI isn't ready yet.

**Exponential backoff**  
Retry delay sequence: 1 s → 2 s → 4 s → 8 s → 16 s → 30 s (cap). Resets to 1 s on successful `onopen`. Stops spamming the backend during startup.

**Page Visibility API**  
`document.addEventListener('visibilitychange', ...)` on mount. When `document.visibilityState === 'visible'` and the socket is not open, cancel any pending timer and call `tryConnect()` immediately. This is the primary fix for the reboot scenario: the moment the user focuses the browser window, reconnect fires — no dead timer to wait for.

**Heartbeat ping**  
After `onopen`, start a `setInterval` every 25 s that sends `{type: 'ping'}` on the socket. Detects silent TCP disconnections (NAT/firewall timeouts) that never fire `onclose`. Clear interval in cleanup and on `onclose`.

**Cleanup**  
`return () => { mountedRef.current = false; clearTimeout; clearInterval; ws.close() }`. All paths covered.

#### State machine summary

```
IDLE ──tryConnect()──▶ HEALTH_CHECK ──ok──▶ CONNECTING ──open──▶ CONNECTED
                           │ fail                │ fail               │
                           └──backoff──────────▶ RETRY ◀────close────┘
                                                    ▲
                           visibilitychange ────────┘ (cancels timer, goes direct)
```

---

### Part 2 — Autonomous Scan Monitor (Claude workflow, no code change)

After the reconnect fix is deployed and the user starts a scan manually, Claude runs:

1. **Tail docker logs** — `docker compose logs -f backend kali` streamed to a temp file
2. **Error watch loop** — inspect logs every ~30 s for:
   - Python tracebacks / `ERROR` lines
   - `AGENT_FAILED` events
   - SSH auth failures, Ollama unreachable, missing env vars
   - Tool timeout storms, LLM fallback loops
3. **Fix cycle** — for each issue:
   - Read relevant source file(s)
   - Diagnose root cause
   - Fix code or config
   - `docker compose restart backend` (or `kali`) as needed
   - Verify `/health` returns 200 before resuming watch
4. **Termination** — loop ends when `ENGAGEMENT_COMPLETED` appears in logs
5. **Report** — summarize all fixes made

**Constraints:**
- Won't modify `.env`, API keys, or scope config without notifying the user
- Won't force-restart mid-agent unless the agent is already failed/hung
- Pauses and asks if a fix requires a credential or config value only the user knows

---

## Files Changed

| File | Change |
|------|--------|
| `frontend/src/App.jsx` | Rewrite `useWebSocket` hook (lines 66–118) |

No backend changes. No new files. No features removed.

---

## Testing

- Turn off Docker → wait 60 s → turn on → confirm status bar recovers without F5
- Open browser tab while backend is down → confirm it reconnects automatically when backend comes up
- Suspend PC → resume → confirm immediate reconnect on focus
- Verify `lastSeq` replay still works (events from downtime appear after reconnect)
- Verify `send()` still works for chat messages and gate confirmations
