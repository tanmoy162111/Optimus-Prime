import { Layers, Lock } from 'lucide-react'

export default function PlanPanel({ plan }) {
  if (!plan) return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Layers size={13} className="text-zinc-500" />
          <span className="label-xs">Engagement Plan</span>
        </div>
      </div>
      <div className="flex flex-col items-center justify-center flex-1 p-6 text-center">
        <Layers size={22} className="text-zinc-700 mb-3" />
        <p className="text-xs text-zinc-600 font-mono">No active plan</p>
        <p className="text-xs text-zinc-700 mt-1">Send a directive to generate an engagement plan</p>
      </div>
    </div>
  )

  const statusColors = {
    pending:    'text-zinc-500',
    active:     'text-emerald-400',
    completed:  'text-zinc-400',
    gate_blocked: 'text-amber-400',
    failed:     'text-red-400',
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Layers size={13} className="text-zinc-500" />
          <span className="label-xs">Engagement Plan</span>
          <span className="font-mono text-xs text-zinc-600">{plan.directive}</span>
        </div>
        <span className="font-mono text-xs text-zinc-600">{plan.plan_id?.slice(0,8)}…</span>
      </div>
      <div className="flex-1 overflow-y-auto p-3">
        <div className="space-y-1.5">
          {plan.phases?.map((phase, i) => {
            const status = phase._status || 'pending'
            return (
              <div key={phase.phase_id}
                className={`flex gap-3 p-3 rounded-lg border transition-all
                  ${status === 'active' ? 'border-emerald-500/30 bg-emerald-500/5' :
                    status === 'completed' ? 'border-zinc-700 bg-zinc-800/30' :
                    status === 'gate_blocked' ? 'border-amber-500/30 bg-amber-500/5' :
                    'border-zinc-800 bg-zinc-800/20'}`}
              >
                <div className="flex flex-col items-center gap-1 shrink-0 pt-0.5">
                  <div className={`w-5 h-5 rounded-full border flex items-center justify-center
                    ${status === 'active' ? 'border-emerald-400 bg-emerald-400/10' :
                      status === 'completed' ? 'border-zinc-600 bg-zinc-700' :
                      status === 'gate_blocked' ? 'border-amber-400 bg-amber-400/10' :
                      'border-zinc-700 bg-zinc-800'}`}>
                    <span className="font-mono text-xs text-zinc-400">{i+1}</span>
                  </div>
                  {i < plan.phases.length - 1 && <div className="w-px h-full bg-zinc-800 flex-1 min-h-4" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-zinc-200">{phase.name}</span>
                    <span className={`font-mono text-xs ${statusColors[status]}`}>{status.toUpperCase()}</span>
                  </div>
                  <p className="text-xs text-zinc-500 mt-0.5 leading-snug">{phase.description}</p>
                  {phase.agents?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {phase.agents.map(a => (
                        <span key={a} className="font-mono text-xs px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-400">{a}</span>
                      ))}
                    </div>
                  )}
                  {phase.gate && (
                    <div className="flex items-center gap-1.5 mt-1.5">
                      <Lock size={11} className="text-amber-400" />
                      <span className="text-xs text-amber-400 font-mono">{phase.gate.description}</span>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
