import { useState, useRef } from 'react'
import { AlertTriangle } from 'lucide-react'

export default function TerminalInput({ agentActive }) {
  const [cmd, setCmd] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  const handleSubmit = async () => {
    const command = cmd.trim()
    if (!command || running) return
    setRunning(true)
    setError(null)
    try {
      const resp = await fetch('/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        setError(err.detail || `HTTP ${resp.status}`)
      } else {
        setCmd('')
      }
    } catch (e) {
      setError(String(e))
    } finally {
      setRunning(false)
      inputRef.current?.focus()
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter') { e.preventDefault(); handleSubmit() }
  }

  return (
    <div className="shrink-0 border-t border-zinc-800">
      {agentActive && (
        <div className="flex items-center gap-2 px-3 py-1 bg-amber-900/20 border-b border-amber-800/40">
          <AlertTriangle size={11} className="text-amber-400 shrink-0" />
          <span className="font-mono text-xs text-amber-400">Agent active — commands will run concurrently</span>
        </div>
      )}
      {error && (
        <div className="px-3 py-1 bg-red-900/20 border-b border-red-800/40">
          <span className="font-mono text-xs text-red-400">{error}</span>
        </div>
      )}
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="font-mono text-xs text-emerald-600 shrink-0 select-none">kali@optimus:~$</span>
        <input
          ref={inputRef}
          type="text"
          value={cmd}
          onChange={e => setCmd(e.target.value)}
          onKeyDown={handleKey}
          disabled={running}
          placeholder="enter command..."
          className="flex-1 bg-transparent font-mono text-xs text-zinc-200 placeholder:text-zinc-700 outline-none disabled:opacity-40"
        />
        <button
          onClick={handleSubmit}
          disabled={running || !cmd.trim()}
          className="font-mono text-xs px-2 py-1 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 hover:bg-zinc-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          {running ? '...' : 'RUN'}
        </button>
      </div>
    </div>
  )
}
