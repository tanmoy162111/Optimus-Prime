import { useState, useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'
import TerminalLine from './TerminalLine'
import TerminalInput from './TerminalInput'

export default function TerminalPanel({ lines, agentActive, wsConnected }) {
  const bottomRef = useRef(null)
  const containerRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, autoScroll])

  const handleScroll = () => {
    const el = containerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    setAutoScroll(atBottom)
  }

  return (
    <div className="panel flex flex-col h-full relative scan-lines">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-zinc-500" />
          <span className="label-xs">Terminal</span>
          {wsConnected && (
            <span className="flex items-center gap-1.5 ml-1">
              <span className="dot-live" />
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-zinc-600">{lines.length} lines</span>
          {!autoScroll && (
            <button
              onClick={() => { setAutoScroll(true); bottomRef.current?.scrollIntoView() }}
              className="btn-ghost text-xs py-1 px-2"
            >
              ↓ resume
            </button>
          )}
        </div>
      </div>

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
      >
        {lines.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <Terminal size={24} className="text-zinc-700 mb-3" />
            <p className="font-mono text-xs text-zinc-600">Waiting for terminal output...</p>
            <p className="text-xs text-zinc-700 mt-1">Start an engagement or type a command below</p>
          </div>
        ) : (
          lines.map((line, i) => <TerminalLine key={i} line={line} />)
        )}
        <div ref={bottomRef} />
      </div>

      <TerminalInput agentActive={agentActive} />
    </div>
  )
}
