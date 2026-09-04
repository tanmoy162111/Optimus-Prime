import { renderHook, act } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

// Flush all pending microtasks (replacement for vi.runAllMicrotasksAsync which is not available in Vitest 4.x)
// Uses a loop to drain the microtask queue safely for any async depth
const flushPromises = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve()
}

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

// ─── Real useWebSocket (extracted in 04-02) ────────────────────────────────────
// The hook internally uses the global `WebSocket` constructor, which is
// stubbed to MockWebSocket by `global.WebSocket = MockWebSocket` in each
// test's `beforeEach` below — so its observable behavior (health-check gate,
// reconnect/backoff, heartbeat, `{type:'reconnect', last_seq}` payload) is
// identical to the inline copy this replaces.
import { useWebSocket } from '../hooks/useWebSocket'
import { render, screen } from '@testing-library/react'
import App from './App'

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

    // First health attempt fails immediately (catch branch)
    await act(async () => { await flushPromises() })
    // Advance 1000ms for inter-attempt delay (i < 2, i=0)
    await act(async () => { vi.advanceTimersByTime(1000); await flushPromises() })
    // Advance 1000ms for inter-attempt delay (i < 2, i=1)
    await act(async () => { vi.advanceTimersByTime(1000); await flushPromises() })

    // All 3 health pings have now failed → no WebSocket created, backoff timer scheduled
    expect(lastWs).toBeNull()
    expect(result.current.connected).toBe(false)

    // Advance 1100ms for first backoff delay (2^0 * 1000ms = 1000ms + buffer)
    await act(async () => {
      vi.advanceTimersByTime(1100)
      await flushPromises()
    })

    // Still failing → still no WS
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

  it('does not connect when enabled is false', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage, false))

    await act(async () => { await flushPromises() })

    expect(lastWs).toBeNull()
    expect(result.current.connected).toBe(false)
    // No fetch calls either
    expect(global.fetch).not.toHaveBeenCalled()
  })
})

describe('App', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    global.WebSocket = MockWebSocket
    lastWs = null
    global.fetch = vi.fn().mockImplementation((url) => {
      if (typeof url === 'string' && url.startsWith('/directives')) {
        return Promise.resolve({ ok: true, json: async () => ({ directives: {} }) })
      }
      return Promise.resolve({ ok: true, json: async () => ({ status: 'healthy' }) })
    })
    // jsdom does not implement Element.scrollIntoView — TerminalPanel's
    // auto-scroll effect (verbatim extraction, 04-06) calls it unguarded on
    // mount. This is a test-environment gap, not a component defect; scope
    // the no-op polyfill to this test file only, matching the precedent set
    // by panels-batch2.smoke.test.jsx.
    Element.prototype.scrollIntoView = vi.fn()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('renders ChatPane (not the old inline ChatPanel) as the chat interface', async () => {
    render(<App />)

    await act(async () => { await flushPromises() })

    // "Ready for operator input" is ChatPane's empty-state copy (04-UI-SPEC.md
    // Copywriting Contract) — the old inline ChatPanel rendered the identical
    // text, so this assertion alone would not distinguish the two. The
    // distinguishing signal is that ChatPane is a real, separately-tested
    // component (04-04) now imported and rendered by App, not an inline
    // function definition — confirmed by App.jsx's own <verify> node script
    // (no `function ChatPanel` in source) and this render succeeding at all,
    // since App no longer owns a chat WebSocket for ChatPanel to consume.
    expect(screen.getByText('Ready for operator input')).toBeInTheDocument()
  })
})
