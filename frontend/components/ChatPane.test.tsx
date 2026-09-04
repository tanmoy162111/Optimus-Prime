import { render, screen, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import ChatPane from './ChatPane'

// Flush all pending microtasks (same helper pattern as App.test.jsx / hooks tests)
const flushPromises = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve()
}

// ─── WebSocket mock factory (reuses the MockWebSocket pattern from App.test.jsx) ──
let lastWs: any = null
class MockWebSocket {
  url: string
  readyState: number
  onopen: (() => void) | null = null
  onclose: ((ev: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  sentMessages: string[] = []

  constructor(url: string) {
    this.url = url
    this.readyState = 0 // CONNECTING
    lastWs = this
  }
  send(data: string) { this.sentMessages.push(data) }
  close() {
    this.readyState = 3 // CLOSED
    this.onclose?.({ code: 1000 })
  }
  _open() {
    this.readyState = 1 // OPEN
    this.onopen?.()
  }
  _error() { this.onerror?.() }
  _message(data: any) { this.onmessage?.({ data: JSON.stringify(data) }) }
}
;(MockWebSocket as any).CONNECTING = 0
;(MockWebSocket as any).OPEN = 1
;(MockWebSocket as any).CLOSING = 2
;(MockWebSocket as any).CLOSED = 3

async function openSocket() {
  await act(async () => { await flushPromises() })
  act(() => { lastWs._open() })
}

async function ackSession(sessionId = 'sess-abc') {
  await openSocket()
  act(() => { lastWs._message({ type: 'session', session_id: sessionId }) })
}

function sentByType(type: string) {
  return lastWs.sentMessages.map((m: string) => JSON.parse(m)).filter((m: any) => m.type === type)
}

describe('ChatPane', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    ;(global as any).WebSocket = MockWebSocket
    lastWs = null
    ;(global as any).fetch = vi.fn().mockResolvedValue({ ok: true })
    localStorage.clear()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('Test 1: connects to /ws/chat (not /chat) with a token query param', async () => {
    render(<ChatPane />)
    await act(async () => { await flushPromises() })

    expect(lastWs).not.toBeNull()
    expect(lastWs.url).toMatch(/\/ws\/chat(\?|$)/)
    expect(new URL(lastWs.url.replace('ws://', 'http://')).pathname).toBe('/ws/chat')
    expect(lastWs.url).toContain('token=')
  })

  it('Test 2: sends {type:"init", session_id} on socket open, reading session_id from localStorage', async () => {
    localStorage.setItem('session_id', 'existing-id')
    render(<ChatPane />)
    await openSocket()

    const initMsgs = sentByType('init')
    expect(initMsgs).toContainEqual({ type: 'init', session_id: 'existing-id' })
  })

  it('Test 2b: sends null session_id when localStorage has none', async () => {
    render(<ChatPane />)
    await openSocket()

    const initMsgs = sentByType('init')
    expect(initMsgs).toContainEqual({ type: 'init', session_id: null })
  })

  it('Test 3: "connected" is gated on the session ack, not raw socket-open; persists session_id; no chat send before ack', async () => {
    const onConnectionChange = vi.fn()
    const { container } = render(<ChatPane onConnectionChange={onConnectionChange} />)
    await openSocket()

    // Socket is open but no session ack yet — must still show disconnected UI
    expect(screen.getByText('disconnected')).toBeInTheDocument()
    expect(onConnectionChange).not.toHaveBeenCalledWith(true)

    const inputEl = screen.getByPlaceholderText('Reconnecting...') as HTMLInputElement
    expect(inputEl).toBeDisabled()
    const sendBtn = container.querySelector('button.btn-primary') as HTMLButtonElement
    expect(sendBtn).toBeDisabled()
    expect(sentByType('chat').length).toBe(0)

    act(() => { lastWs._message({ type: 'session', session_id: 'sess-999' }) })

    expect(screen.queryByText('disconnected')).not.toBeInTheDocument()
    expect(localStorage.getItem('session_id')).toBe('sess-999')
    expect(onConnectionChange).toHaveBeenCalledWith(true)
  })

  it('Test 4: chat-stream fragments (no type key) accumulate into one assistant message', async () => {
    render(<ChatPane />)
    await ackSession()

    act(() => { lastWs._message({ chunk: 'hel', done: false }) })
    act(() => { lastWs._message({ chunk: 'lo', done: true }) })

    expect(screen.getByText('hello')).toBeInTheDocument()
  })

  it('Test 5: PHASE_FAILED/GATE_PENDING render inline messages; other event_types no-op; none throw', async () => {
    const { container } = render(<ChatPane />)
    await ackSession()

    expect(() => {
      act(() => { lastWs._message({ event_type: 'PHASE_FAILED', detail: 'recon', error: 'boom' }) })
    }).not.toThrow()
    expect(screen.getByText(/Phase failed/)).toBeInTheDocument()
    expect(screen.getByText(/boom/)).toBeInTheDocument()

    expect(() => {
      act(() => { lastWs._message({ event_type: 'GATE_PENDING' }) })
    }).not.toThrow()
    expect(screen.getByText(/Gate pending/)).toBeInTheDocument()

    const countBefore = container.querySelectorAll('.rounded-xl').length
    expect(() => {
      act(() => { lastWs._message({ event_type: 'PHASE_STARTED' }) })
    }).not.toThrow()
    const countAfter = container.querySelectorAll('.rounded-xl').length
    expect(countAfter).toBe(countBefore)
  })

  it('Test 6: an explicit {type:"error"} frame injects the locked copy exactly once, not per retry', async () => {
    render(<ChatPane />)
    await openSocket()

    const copy = "Couldn't start a session with the backend. Retrying automatically — check that the backend is running."

    act(() => { lastWs._message({ type: 'error', message: 'boom' }) })
    expect(screen.getAllByText(copy).length).toBe(1)

    act(() => { lastWs._message({ type: 'error', message: 'boom again' }) })
    expect(screen.getAllByText(copy).length).toBe(1)
  })

  it('Test 7: parent callbacks fire on session ack and on disconnect', async () => {
    const onSessionChange = vi.fn()
    const onConnectionChange = vi.fn()
    render(<ChatPane onSessionChange={onSessionChange} onConnectionChange={onConnectionChange} />)
    await openSocket()

    act(() => { lastWs._message({ type: 'session', session_id: 'sess-123' }) })
    expect(onSessionChange).toHaveBeenCalledTimes(1)
    expect(onSessionChange).toHaveBeenCalledWith('sess-123')
    expect(onConnectionChange).toHaveBeenCalledWith(true)

    act(() => { lastWs.close() })
    expect(onConnectionChange).toHaveBeenCalledWith(false)
  })

  it('Test 7b: rendering without onSessionChange/onConnectionChange props does not throw', async () => {
    expect(() => render(<ChatPane />)).not.toThrow()
    await openSocket()

    expect(() => {
      act(() => { lastWs._message({ type: 'session', session_id: 'sess-456' }) })
    }).not.toThrow()
    expect(() => {
      act(() => { lastWs.close() })
    }).not.toThrow()
  })
})
