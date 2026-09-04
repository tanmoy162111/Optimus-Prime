import { useState, useRef, useCallback, useEffect } from 'react'
import { Terminal, Lock, Send } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'
import ChatMessage from './ChatMessage'

interface ChatMsg {
  role: 'user' | 'assistant'
  type?: string
  content: string
  metadata?: { tokens?: number; model?: string }
  done?: boolean
}

interface GateInfo {
  gate_event_id: string
  description?: string
}

interface ChatPaneProps {
  pendingGate?: GateInfo | null
  onGateResolve?: (gateEventId: string, action: 'confirm' | 'skip') => void
  onSessionChange?: (sessionId: string) => void
  onConnectionChange?: (acked: boolean) => void
}

// Locked copy — 04-UI-SPEC.md Copywriting Contract, "Error state — chat handshake failure"
const HANDSHAKE_ERROR_COPY =
  "Couldn't start a session with the backend. Retrying automatically — check that the backend is running."

// Source: backend/app.py include_router(ws_handler.router, prefix="/ws");
// backend/api/ws_handler.py @router.websocket("/chat") => real path is /ws/chat (D-01)
// backend/auth.py verify_ws_token() requires ?token= (D-11, T-04-WS-AUTH mitigation)
const WS_BASE = typeof window !== 'undefined' ? `ws://${window.location.host}` : 'ws://localhost'

export default function ChatPane({ pendingGate, onGateResolve, onSessionChange, onConnectionChange }: ChatPaneProps) {
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [input, setInput] = useState('')
  const [sessionAcked, setSessionAcked] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const wasConnectedRef = useRef(false)
  const sessionAckedRef = useRef(false)
  const handshakeErrorShownRef = useRef(false)

  const token = (import.meta as any).env?.VITE_BEARER_TOKEN || 'dev-token'
  const chatUrl = `${WS_BASE}/ws/chat?token=${encodeURIComponent(token)}`

  // Three payload shapes on this one socket, branch on key presence not a single
  // data.type switch — D-12 / RESEARCH.md Pattern 3 / Pitfall 4.
  const handleSocketMessage = useCallback((data: any) => {
    if (data.type) {
      switch (data.type) {
        case 'session':
          try { localStorage.setItem('session_id', data.session_id) } catch {}
          sessionAckedRef.current = true
          handshakeErrorShownRef.current = false
          setSessionAcked(true)
          onSessionChange?.(data.session_id)
          onConnectionChange?.(true)
          break
        case 'error':
          if (!handshakeErrorShownRef.current) {
            handshakeErrorShownRef.current = true
            setMessages(prev => [...prev, { role: 'assistant', type: 'error', content: HANDSHAKE_ERROR_COPY }])
          }
          break
        // 'welcome' / 'pong' — no UI action needed
        default:
          break
      }
      return
    }

    if ('chunk' in data || 'done' in data) {
      if (data.chunk) {
        setMessages(prev => {
          const last = prev[prev.length - 1]
          if (last && last.role === 'assistant' && !last.done) {
            return [...prev.slice(0, -1), { ...last, content: last.content + data.chunk }]
          }
          return [...prev, { role: 'assistant', content: data.chunk }]
        })
      }
      if (data.done) {
        setMessages(prev => {
          const last = prev[prev.length - 1]
          if (last && last.role === 'assistant') {
            return [...prev.slice(0, -1), { ...last, done: true }]
          }
          return prev
        })
      }
      return
    }

    if (data.event_type) {
      // Clawhip lifecycle events arrive on this same socket (D-12, RESEARCH.md Pitfall 4).
      // PHASE_FAILED/GATE_PENDING render inline; every other event_type is a no-op —
      // never falls through to chat-content rendering.
      if (data.event_type === 'PHASE_FAILED') {
        const detailSuffix = data.detail ? ` (${data.detail})` : ''
        const errorSuffix = data.error ? `: ${data.error}` : ''
        setMessages(prev => [...prev, { role: 'assistant', type: 'error', content: `Phase failed${detailSuffix}${errorSuffix}` }])
      } else if (data.event_type === 'GATE_PENDING') {
        setMessages(prev => [...prev, { role: 'assistant', type: 'error', content: 'Gate pending — awaiting operator confirmation.' }])
      }
      return
    }
  }, [onSessionChange, onConnectionChange])

  const { connected, send } = useWebSocket(chatUrl, handleSocketMessage)

  // On socket open, send the handshake init frame (D-03). "Connected" for the UI/parent
  // means session-acked, not merely socket-open — reset that state on disconnect.
  useEffect(() => {
    if (connected && !wasConnectedRef.current) {
      let storedId: string | null = null
      try { storedId = localStorage.getItem('session_id') } catch {}
      send({ type: 'init', session_id: storedId || null })
    }
    if (!connected && sessionAckedRef.current) {
      sessionAckedRef.current = false
      setSessionAcked(false)
      onConnectionChange?.(false)
    }
    wasConnectedRef.current = connected
  }, [connected, send, onConnectionChange])

  useEffect(() => {
    bottomRef.current?.scrollIntoView?.({ behavior: 'smooth' })
  }, [messages])

  const handleSend = useCallback(() => {
    const text = input.trim()
    if (!text || !sessionAcked) return
    setMessages(prev => [...prev, { role: 'user', content: text }])
    setInput('')
    send({ type: 'chat', message: text, mode: null })
    inputRef.current?.focus()
  }, [input, sessionAcked, send])

  const handleKey = (e: any) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-zinc-500" />
          <span className="label-xs">Operator Console</span>
          {sessionAcked ? (
            <span className="flex items-center gap-1.5"><span className="dot-live" /></span>
          ) : (
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-500" />
              <span className="font-mono text-xs text-red-400">disconnected</span>
            </span>
          )}
        </div>
        {pendingGate && (
          <div className="flex items-center gap-2 animate-pulse-slow">
            <Lock size={12} className="text-amber-400" />
            <span className="font-mono text-xs text-amber-400">gate awaiting</span>
            <button
              onClick={() => onGateResolve?.(pendingGate.gate_event_id, 'confirm')}
              className="font-mono text-xs px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/30 transition-colors"
            >
              confirm
            </button>
            <button
              onClick={() => onGateResolve?.(pendingGate.gate_event_id, 'skip')}
              className="font-mono text-xs px-2 py-0.5 rounded bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500/30 transition-colors"
            >
              skip
            </button>
          </div>
        )}
      </div>

      {/* Message history */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Terminal size={22} className="text-zinc-700 mb-3" />
            <p className="font-mono text-xs text-zinc-600">Ready for operator input</p>
            <p className="text-xs text-zinc-700 mt-1">Try: <span className="font-mono text-zinc-500">$recon</span> or <span className="font-mono text-zinc-500">$pentest</span></p>
          </div>
        )}
        {messages.map((msg, i) => (
          <ChatMessage key={i} msg={msg} />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Hint chips */}
      <div className="px-4 pb-2 flex gap-2 flex-wrap shrink-0">
        {['$recon', '$pentest', '$cloud-audit', '$scope-discover'].map(d => (
          <button
            key={d}
            onClick={() => { setInput(d + ' '); inputRef.current?.focus() }}
            className="font-mono text-xs px-2 py-1 rounded bg-zinc-800 border border-zinc-700
                       text-zinc-500 hover:text-zinc-300 hover:border-zinc-600 transition-colors"
          >
            {d}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="px-4 pb-4 flex gap-2 shrink-0">
        <input
          ref={inputRef}
          className="input-field flex-1 text-sm"
          placeholder={sessionAcked ? 'Type a directive or message...' : 'Reconnecting...'}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          disabled={!sessionAcked}
        />
        <button
          className="btn-primary px-3 shrink-0"
          onClick={handleSend}
          disabled={!input.trim() || !sessionAcked}
        >
          <Send size={14} />
        </button>
      </div>
    </div>
  )
}
