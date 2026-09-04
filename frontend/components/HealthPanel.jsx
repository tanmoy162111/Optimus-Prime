import { Activity, RefreshCw } from 'lucide-react'

export default function HealthPanel({ health, onRefresh }) {
  const items = health ? [
    { label: 'Version', value: health.version },
    { label: 'Milestone', value: health.milestone },
    { label: 'Kali SSH', value: health.kali_connected ? 'Connected' : 'Offline', ok: health.kali_connected },
    { label: 'Token Budget', value: health.budget_remaining?.toLocaleString(), ok: (health.budget_remaining ?? 1) > 0 },
  ] : []

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Activity size={13} className="text-zinc-500" />
          <span className="label-xs">System Health</span>
        </div>
        <button onClick={onRefresh} className="btn-ghost p-1">
          <RefreshCw size={12} />
        </button>
      </div>
      <div className="p-3">
        {!health ? (
          <div className="flex items-center gap-2 py-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-500" />
            <span className="font-mono text-xs text-red-400">Backend unreachable</span>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
            {items.map(({ label, value, ok }) => (
              <div key={label} className="flex items-center justify-between gap-2">
                <span className="label-xs">{label}</span>
                <span className={`font-mono text-xs font-medium ${
                  ok === undefined ? 'text-zinc-300' : ok ? 'text-emerald-400' : 'text-red-400'
                }`}>{value ?? '—'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
