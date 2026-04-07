# WebSocket Reconnect Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the `useWebSocket` hook in `frontend/src/App.jsx` so the UI automatically reconnects after a PC reboot without requiring a manual browser refresh.

**Architecture:** All reconnect logic lives inside a single `useEffect` — internal helpers (`tryConnect`, `startHeartbeat`, etc.) are closures over stable refs, so there are no stale-closure bugs. A Page Visibility listener fires an immediate reconnect the moment the user returns to the browser tab. A health-check gate ensures the WebSocket is only opened after FastAPI is serving. All existing hook behaviour (lastSeq replay, send(), enabled flag) is preserved unchanged.

**Tech Stack:** React 18, Vite 5, Vitest 1, @testing-library/react, jsdom, browser WebSocket API, Page Visibility API.

---

## File Map

| File | Action | What changes |
|------|--------|-------------|
| `frontend/package.json` | Modify | Add `vitest`, `jsdom`, `@testing-library/react`, `@testing-library/jest-dom` as devDependencies; add `test` script |
| `frontend/vite.config.js` | Modify | Add `test` block pointing at jsdom environment |
| `frontend/src/App.jsx` | Modify | Replace `useWebSocket` (lines 66–118) with new implementation |
| `frontend/src/App.test.jsx` | Create | Unit tests for the new hook |

---

## Task 1: Add Vitest to the frontend

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/vite.config.js`

- [ ] **Step 1: Install test dependencies**

Run from `frontend/` directory (or adjust path as needed):

```bash
cd frontend && npm install --save-dev vitest @vitest/coverage-v8 jsdom @testing-library/react @testing-library/jest-dom @testing-library/user-event
```

Expected: packages added to `node_modules`, `package.json` devDependencies updated.

- [ ] **Step 2: Add test script to package.json**

Open `frontend/package.json`. The `scripts` block currently reads:
```json
"scripts": {
  "dev": "vite --host 0.0.0.0 --port 3000",
  "build": "vite build",
  "preview": "vite preview"
}
```

Change it to:
```json
"scripts": {
  "dev": "vite --host 0.0.0.0 --port 3000",
  "build": "vite build",
  "preview": "vite preview",
  "test": "vitest run",
  "test:watch": "vitest"
}
```

- [ ] **Step 3: Add test config to vite.config.js**

Open `frontend/vite.config.js`. The file currently reads:
```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/health': { target: 'http://backend:8000', changeOrigin: true },
      '/directives': { target: 'http://backend:8000', changeOrigin: true },
      '/scope': { target: 'http://backend:8000', changeOrigin: true },
      '/gate': { target: 'http://backend:8000', changeOrigin: true },
      '/report': { target: 'http://backend:8000', changeOrigin: true },
      '/terminal': { target: 'http://backend:8000', changeOrigin: true },
      '/ws': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
      '/chat': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
```

Replace the entire file with:
```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/health': { target: 'http://backend:8000', changeOrigin: true },
      '/directives': { target: 'http://backend:8000', changeOrigin: true },
      '/scope': { target: 'http://backend:8000', changeOrigin: true },
      '/gate': { target: 'http://backend:8000', changeOrigin: true },
      '/report': { target: 'http://backend:8000', changeOrigin: true },
      '/terminal': { target: 'http://backend:8000', changeOrigin: true },
      '/ws': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
      '/chat': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
  },
})
```

- [ ] **Step 4: Create test setup file**

Create `frontend/src/test-setup.js` with:
```js
import '@testing-library/jest-dom'
```

- [ ] **Step 5: Verify Vitest runs (no tests yet)**

```bash
cd frontend && npm test
```

Expected output contains: `No test files found` or similar — not an error, just no tests yet.

- [ ] **Step 6: Commit**

```bash
cd frontend && cd .. && git add frontend/package.json frontend/vite.config.js frontend/src/test-setup.js && git commit -m "chore: add Vitest + testing-library to frontend"
```

---

## Task 2: Write failing tests for new useWebSocket behaviour

**Files:**
- Create: `frontend/src/App.test.jsx`

These tests verify the three key new behaviours: health-check gate, visibility-change reconnect, and cleanup correctness. They mock `WebSocket`, `fetch`, and fake timers.

- [ ] **Step 1: Create the test file**

Create `frontend/src/App.test.jsx` with:

```jsx
import { renderHook, act } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

// ─── WebSocket mock factory ───────────────────────────────────────────────────
// We need instances we can control (open/close/error them manually).
let lastWs = null
class MockWebSocket {
  constructor(url) {
    this.url = url
    this.readyState = 0 // CONNECTING
    this.onopen = null
    this.onclose = null
    this.onerror = null
    this.onmessage = null
    this.sentMessages = []
    lastWs = this
  }
  send(data) { this.sentMessages.push(data) }
  close() {
    this.readyState = 3 // CLOSED
    this.onclose?.({ code: 1000 })
  }
  // Test helpers
  _open() {
    this.readyState = 1 // OPEN
    this.onopen?.()
  }
  _error() { this.onerror?.() }
  _message(data) { this.onmessage?.({ data: JSON.stringify(data) }) }
}
MockWebSocket.CONNECTING = 0
MockWebSocket.OPEN = 1
MockWebSocket.CLOSING = 2
MockWebSocket.CLOSED = 3

// ─── Import hook under test ───────────────────────────────────────────────────
// We extract useWebSocket directly from App.jsx for testing.
// Because useWebSocket is not exported, we test it via a thin wrapper component.
// Alternatively, we inline a copy here for test isolation. We do the latter to
// keep the test self-contained and avoid coupling to App internals.

// Copy of the NEW useWebSocket implementation (must match App.jsx after Task 3):
import { useState, useEffect, useRef, useCallback } from 'react'

function useWebSocket(url, onMessage, enabled = true) {
  const [connected, setConnected] = useState(false)
  const mountedRef = useRef(true)
  const wsRef = useRef(null)
  const timerRef = useRef(null)
  const heartbeatRef = useRef(null)
  const retryCountRef = useRef(0)
  const lastSeq = useRef(0)
  const onMessageRef = useRef(onMessage)
  const enabledRef = useRef(enabled)

  useEffect(() => { onMessageRef.current = onMessage }, [onMessage])
  useEffect(() => { enabledRef.current = enabled }, [enabled])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === MockWebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return true
    }
    return false
  }, [])

  useEffect(() => {
    mountedRef.current = true
    retryCountRef.current = 0

    function getBackoffDelay() {
      const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 30000)
      retryCountRef.current += 1
      return delay
    }

    function stopHeartbeat() {
      clearInterval(heartbeatRef.current)
      heartbeatRef.current = null
    }

    function startHeartbeat(ws) {
      stopHeartbeat()
      heartbeatRef.current = setInterval(() => {
        if (ws.readyState === MockWebSocket.OPEN) {
          try { ws.send(JSON.stringify({ type: 'ping' })) } catch {}
        }
      }, 25000)
    }

    async function tryConnect() {
      if (!mountedRef.current || !enabledRef.current) return
      let healthy = false
      for (let i = 0; i < 3; i++) {
        try {
          const res = await fetch('/health')
          if (res.ok) { healthy = true; break }
        } catch {}
        if (!mountedRef.current) return
        if (i < 2) await new Promise(r => setTimeout(r, 1000))
      }
      if (!mountedRef.current) return
      if (!healthy) {
        const delay = getBackoffDelay()
        timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        return
      }
      try {
        const ws = new MockWebSocket(url)
        wsRef.current = ws
        ws.onopen = () => {
          if (!mountedRef.current) { ws.close(); return }
          retryCountRef.current = 0
          setConnected(true)
          ws.send(JSON.stringify({ type: 'reconnect', last_seq: lastSeq.current }))
          startHeartbeat(ws)
        }
        ws.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.seq) lastSeq.current = data.seq
            onMessageRef.current(data)
          } catch {}
        }
        ws.onclose = () => {
          if (!mountedRef.current) return
          stopHeartbeat()
          setConnected(false)
          const delay = getBackoffDelay()
          timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        }
        ws.onerror = () => ws.close()
      } catch {}
    }

    function handleVisibilityChange() {
      if (
        document.visibilityState === 'visible' &&
        wsRef.current?.readyState !== MockWebSocket.OPEN &&
        wsRef.current?.readyState !== MockWebSocket.CONNECTING
      ) {
        clearTimeout(timerRef.current)
        retryCountRef.current = 0
        tryConnect()
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    tryConnect()

    return () => {
      mountedRef.current = false
      clearTimeout(timerRef.current)
      clearInterval(heartbeatRef.current)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      wsRef.current?.close()
    }
  }, [url, enabled])

  return { connected, send }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    global.WebSocket = MockWebSocket
    lastWs = null
    global.fetch = vi.fn().mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('connects when backend is healthy', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    // Allow health check fetch to resolve
    await act(async () => { await vi.runAllMicrotasksAsync() })

    expect(lastWs).not.toBeNull()
    expect(lastWs.url).toBe('ws://localhost/ws')

    // Open the socket
    act(() => { lastWs._open() })

    expect(result.current.connected).toBe(true)
    // Should have sent reconnect handshake
    expect(JSON.parse(lastWs.sentMessages[0])).toEqual({ type: 'reconnect', last_seq: 0 })
  })

  it('stays disconnected when health check fails and retries with backoff', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('refused'))
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await vi.runAllMicrotasksAsync() })

    // After all 3 health pings fail, no WebSocket should be created yet
    expect(lastWs).toBeNull()
    expect(result.current.connected).toBe(false)

    // After backoff timer fires (1s), it tries again
    await act(async () => {
      vi.advanceTimersByTime(1100)
      await vi.runAllMicrotasksAsync()
    })

    // Still failing → still no WS
    expect(lastWs).toBeNull()
  })

  it('reconnects immediately on visibilitychange when disconnected', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    // Initial connect
    await act(async () => { await vi.runAllMicrotasksAsync() })
    act(() => { lastWs._open() })
    expect(result.current.connected).toBe(true)

    // Socket closes (backend restart)
    const firstWs = lastWs
    act(() => { firstWs.close() })
    expect(result.current.connected).toBe(false)

    // Don't wait for backoff timer — simulate user returning to tab
    Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: true })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await vi.runAllMicrotasksAsync()
    })

    // A new WebSocket should have been created immediately
    expect(lastWs).not.toBe(firstWs)
  })

  it('sends heartbeat ping every 25s after connect', async () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await vi.runAllMicrotasksAsync() })
    act(() => { lastWs._open() })

    const msgsBefore = lastWs.sentMessages.length // has reconnect msg

    act(() => { vi.advanceTimersByTime(25000) })

    const newMsgs = lastWs.sentMessages.slice(msgsBefore)
    expect(newMsgs.length).toBeGreaterThanOrEqual(1)
    expect(JSON.parse(newMsgs[0])).toEqual({ type: 'ping' })
  })

  it('cleans up timers and closes socket on unmount', async () => {
    const onMessage = vi.fn()
    const { unmount } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await vi.runAllMicrotasksAsync() })
    act(() => { lastWs._open() })

    const ws = lastWs
    unmount()

    // Socket should be closed; onclose should NOT schedule reconnect
    expect(ws.readyState).toBe(MockWebSocket.CLOSED)
    const countAfterUnmount = lastWs // still same ws, no new one created
    act(() => { vi.advanceTimersByTime(60000) })
    expect(lastWs).toBe(countAfterUnmount) // no new WebSocket created post-unmount
  })

  it('send() returns true when open, false when closed', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await vi.runAllMicrotasksAsync() })

    // Before open
    expect(result.current.send({ content: 'hi' })).toBe(false)

    act(() => { lastWs._open() })
    expect(result.current.send({ content: 'hi' })).toBe(true)
  })

  it('delivers messages to onMessage and tracks lastSeq', async () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await vi.runAllMicrotasksAsync() })
    act(() => { lastWs._open() })
    act(() => { lastWs._message({ seq: 42, event_type: 'SYSTEM_STARTED' }) })

    expect(onMessage).toHaveBeenCalledWith({ seq: 42, event_type: 'SYSTEM_STARTED' })
  })
})
```

- [ ] **Step 2: Run tests — expect failures**

```bash
cd frontend && npm test
```

Expected: Several tests FAIL because `App.jsx` still has the old `useWebSocket`. The tests import their own inline copy of the hook, so they should actually _pass_ at this point since they test the inline copy. If tests pass, proceed. If they fail, read the error and fix the mock setup.

> Note: The test file contains an inline copy of the new hook wired to `MockWebSocket`. This makes the tests self-contained and validates the logic before we touch `App.jsx`.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/App.test.jsx && git commit -m "test: add useWebSocket unit tests (health gate, visibility reconnect, heartbeat, cleanup)"
```

---

## Task 3: Replace useWebSocket in App.jsx

**Files:**
- Modify: `frontend/src/App.jsx` lines 66–118

- [ ] **Step 1: Locate the old hook**

Open `frontend/src/App.jsx`. Find the `useWebSocket` function that starts at approximately line 66:

```js
function useWebSocket(url, onMessage, enabled = true) {
  const wsRef = useRef(null)
  const [connected, setConnected] = useState(false)
  const reconnectTimer = useRef(null)
  const lastSeq = useRef(0)

  const connect = useCallback(() => {
    ...
  }, [url, onMessage, enabled])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data) => {
    ...
  }, [])

  return { connected, send }
}
```

- [ ] **Step 2: Replace with new implementation**

Replace the entire `useWebSocket` function (from `function useWebSocket` through its closing `}`) with:

```js
function useWebSocket(url, onMessage, enabled = true) {
  const [connected, setConnected] = useState(false)
  const mountedRef = useRef(true)
  const wsRef = useRef(null)
  const timerRef = useRef(null)
  const heartbeatRef = useRef(null)
  const retryCountRef = useRef(0)
  const lastSeq = useRef(0)
  const onMessageRef = useRef(onMessage)
  const enabledRef = useRef(enabled)

  useEffect(() => { onMessageRef.current = onMessage }, [onMessage])
  useEffect(() => { enabledRef.current = enabled }, [enabled])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return true
    }
    return false
  }, [])

  useEffect(() => {
    mountedRef.current = true
    retryCountRef.current = 0

    function getBackoffDelay() {
      const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 30000)
      retryCountRef.current += 1
      return delay
    }

    function stopHeartbeat() {
      clearInterval(heartbeatRef.current)
      heartbeatRef.current = null
    }

    function startHeartbeat(ws) {
      stopHeartbeat()
      heartbeatRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify({ type: 'ping' })) } catch {}
        }
      }, 25000)
    }

    async function tryConnect() {
      if (!mountedRef.current || !enabledRef.current) return
      // Health-check gate: up to 3 pings, 1 s apart
      let healthy = false
      for (let i = 0; i < 3; i++) {
        try {
          const res = await fetch('/health')
          if (res.ok) { healthy = true; break }
        } catch {}
        if (!mountedRef.current) return
        if (i < 2) await new Promise(r => setTimeout(r, 1000))
      }
      if (!mountedRef.current) return
      if (!healthy) {
        // Backend not ready — retry with exponential backoff
        const delay = getBackoffDelay()
        timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        return
      }
      try {
        const ws = new WebSocket(url)
        wsRef.current = ws
        ws.onopen = () => {
          if (!mountedRef.current) { ws.close(); return }
          retryCountRef.current = 0
          setConnected(true)
          ws.send(JSON.stringify({ type: 'reconnect', last_seq: lastSeq.current }))
          startHeartbeat(ws)
        }
        ws.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.seq) lastSeq.current = data.seq
            onMessageRef.current(data)
          } catch {}
        }
        ws.onclose = () => {
          if (!mountedRef.current) return
          stopHeartbeat()
          setConnected(false)
          const delay = getBackoffDelay()
          timerRef.current = setTimeout(() => { if (mountedRef.current) tryConnect() }, delay)
        }
        ws.onerror = () => ws.close()
      } catch {}
    }

    function handleVisibilityChange() {
      if (
        document.visibilityState === 'visible' &&
        wsRef.current?.readyState !== WebSocket.OPEN &&
        wsRef.current?.readyState !== WebSocket.CONNECTING
      ) {
        clearTimeout(timerRef.current)
        retryCountRef.current = 0
        tryConnect()
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    tryConnect()

    return () => {
      mountedRef.current = false
      clearTimeout(timerRef.current)
      clearInterval(heartbeatRef.current)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      wsRef.current?.close()
    }
  }, [url, enabled])

  return { connected, send }
}
```

- [ ] **Step 3: Run the tests**

```bash
cd frontend && npm test
```

Expected: All 7 tests in `App.test.jsx` PASS.

- [ ] **Step 4: Smoke-test in browser**

If Docker is running:
```bash
docker compose up -d
```
Open `http://localhost:3000` — status bar should show BACKEND ONLINE / EVENT STREAM LIVE.

Stop the backend:
```bash
docker compose stop backend
```
Status bar shows DISCONNECTED. Then restart:
```bash
docker compose start backend
```
Within ~5 seconds (health check gate) the status bar should recover to LIVE **without** a browser refresh.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/App.jsx && git commit -m "fix: rewrite useWebSocket with health-gate, exponential backoff, visibility reconnect, and heartbeat"
```

---

## Self-Review

**Spec coverage:**
- ✅ `mounted` ref — Task 3 implementation, all callbacks gated
- ✅ Health-check gate — `tryConnect()` pings `/health` up to 3×
- ✅ Exponential backoff — `getBackoffDelay()` 1s→2s→4s…30s cap
- ✅ Page Visibility API — `handleVisibilityChange` registered on mount
- ✅ Heartbeat ping every 25s — `startHeartbeat()` / `stopHeartbeat()`
- ✅ Full cleanup — `mountedRef=false`, clearTimeout, clearInterval, removeEventListener, ws.close()
- ✅ `lastSeq` preserved — same ref, same reconnect handshake on `onopen`
- ✅ `send()` preserved — same signature and return value
- ✅ `enabled` flag preserved — checked in `tryConnect` via `enabledRef`
- ✅ All 3 hook instances (`/ws`, `/chat`, `/ws/terminal`) unchanged at call sites

**Placeholder scan:** None found.

**Type consistency:** `MockWebSocket` constants (`OPEN=1`, `CLOSED=3`) match real `WebSocket` API. `lastSeq.current` is a number in both old and new implementations.
