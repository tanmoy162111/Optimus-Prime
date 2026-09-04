import { useState, useEffect } from 'react'
import { Shield } from 'lucide-react'
import { fmtElapsed } from '../lib/format'

export default function StatusBar({ health, wsEvents, wsChat, engagementActive, startTime }) {
  const items = [
    {
      label: 'BACKEND',
      ok: health !== null,
      value: health ? 'ONLINE' : 'OFFLINE',
    },
    {
      label: 'EVENT STREAM',
      ok: wsEvents,
      value: wsEvents ? 'LIVE' : 'DISCONNECTED',
    },
    {
      label: 'CHAT',
      ok: wsChat,
      value: wsChat ? 'READY' : 'DISCONNECTED',
    },
    {
      label: 'KALI',
      ok: health?.kali_connected,
      value: health?.kali_connected ? 'CONNECTED' : 'OFFLINE',
    },
    {
      label: 'TOKEN BUDGET',
      ok: (health?.budget_remaining ?? 1) > 0,
      value: health?.budget_remaining != null
        ? `${health.budget_remaining.toLocaleString()} remaining`
        : '—',
    },
  ]

  return (
    <div className="flex items-center gap-0 border-b border-zinc-800 bg-zinc-950 px-4 h-9 shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2 pr-6 border-r border-zinc-800 mr-4">
        <Shield size={14} className="text-white" strokeWidth={2.5} />
        <span className="font-mono text-xs font-semibold tracking-[0.2em] text-white">OPTIMUS PRIME</span>
        <span className="font-mono text-xs text-zinc-600 ml-1">v2.0</span>
      </div>

      {/* Status items */}
      <div className="flex items-center gap-5 flex-1">
        {items.map(({ label, ok, value }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className={`inline-block w-1.5 h-1.5 rounded-full ${ok ? 'bg-emerald-400' : 'bg-red-500'}`} />
            <span className="label-xs">{label}</span>
            <span className={`font-mono text-xs ${ok ? 'text-zinc-300' : 'text-red-400'}`}>{value}</span>
          </div>
        ))}
      </div>

      {/* Engagement timer */}
      {engagementActive && startTime && (
        <div className="flex items-center gap-2 pl-4 border-l border-zinc-800">
          <span className="dot-live" />
          <span className="label-xs">ENGAGEMENT</span>
          <EngagementTimer startTime={startTime} />
        </div>
      )}

      {/* Milestone */}
      <div className="pl-4 border-l border-zinc-800 ml-4">
        <span className="label-xs">M3</span>
      </div>
    </div>
  )
}

function EngagementTimer({ startTime }) {
  const [elapsed, setElapsed] = useState(fmtElapsed(startTime))
  useEffect(() => {
    const t = setInterval(() => setElapsed(fmtElapsed(startTime)), 1000)
    return () => clearInterval(t)
  }, [startTime])
  return <span className="font-mono text-xs text-emerald-400">{elapsed}</span>
}
