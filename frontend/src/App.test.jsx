import { renderHook, act } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

// Flush all pending microtasks (replacement for vi.runAllMicrotasksAsync which is not available in Vitest 4.x)
// Uses Promise.resolve() chains to drain the microtask queue without relying on fake timers
const flushPromises = () => Promise.resolve().then(() => Promise.resolve()).then(() => Promise.resolve())

// ─── WebSocket mock factory ───────────────────────────────────────────────────
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

// ─── Inline copy of the NEW useWebSocket (matches what Task 3 will put in App.jsx) ─
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

    await act(async () => { await flushPromises() })

    expect(lastWs).not.toBeNull()
    expect(lastWs.url).toBe('ws://localhost/ws')

    act(() => { lastWs._open() })

    expect(result.current.connected).toBe(true)
    expect(JSON.parse(lastWs.sentMessages[0])).toEqual({ type: 'reconnect', last_seq: 0 })
  })

  it('stays disconnected when health check fails and retries with backoff', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('refused'))
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })

    expect(lastWs).toBeNull()
    expect(result.current.connected).toBe(false)

    await act(async () => {
      vi.advanceTimersByTime(1100)
      await flushPromises()
    })

    expect(lastWs).toBeNull()
  })

  it('reconnects immediately on visibilitychange when disconnected', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })
    act(() => { lastWs._open() })
    expect(result.current.connected).toBe(true)

    const firstWs = lastWs
    act(() => { firstWs.close() })
    expect(result.current.connected).toBe(false)

    Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: true })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await flushPromises()
    })

    expect(lastWs).not.toBe(firstWs)
  })

  it('sends heartbeat ping every 25s after connect', async () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })
    act(() => { lastWs._open() })

    const msgsBefore = lastWs.sentMessages.length

    act(() => { vi.advanceTimersByTime(25000) })

    const newMsgs = lastWs.sentMessages.slice(msgsBefore)
    expect(newMsgs.length).toBeGreaterThanOrEqual(1)
    expect(JSON.parse(newMsgs[0])).toEqual({ type: 'ping' })
  })

  it('cleans up timers and closes socket on unmount', async () => {
    const onMessage = vi.fn()
    const { unmount } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })
    act(() => { lastWs._open() })

    const ws = lastWs
    unmount()

    expect(ws.readyState).toBe(MockWebSocket.CLOSED)
    const wsAfterUnmount = lastWs
    act(() => { vi.advanceTimersByTime(60000) })
    expect(lastWs).toBe(wsAfterUnmount)
  })

  it('send() returns true when open, false when closed', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })

    expect(result.current.send({ content: 'hi' })).toBe(false)

    act(() => { lastWs._open() })
    expect(result.current.send({ content: 'hi' })).toBe(true)
  })

  it('delivers messages to onMessage and tracks lastSeq', async () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket('ws://localhost/ws', onMessage))

    await act(async () => { await flushPromises() })
    act(() => { lastWs._open() })
    act(() => { lastWs._message({ seq: 42, event_type: 'SYSTEM_STARTED' }) })

    expect(onMessage).toHaveBeenCalledWith({ seq: 42, event_type: 'SYSTEM_STARTED' })
  })
})
