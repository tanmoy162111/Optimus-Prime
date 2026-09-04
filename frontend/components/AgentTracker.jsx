import { Cpu } from 'lucide-react'

export default function AgentTracker({ agents }) {
  const statusColors = {
    spawning:        'text-zinc-500',
    trust_required:  'text-amber-400',
    ready_for_prompt:'text-sky-400',
    running:         'text-emerald-400',
    finished:        'text-zinc-400',
    failed:          'text-red-400',
    completed:       'text-zinc-400',
  }
  const statusDots = {
    running:  'bg-emerald-400 animate-pulse-slow',
    failed:   'bg-red-400',
    finished: 'bg-zinc-600',
    completed:'bg-zinc-600',
    spawning: 'bg-zinc-500',
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Cpu size={13} className="text-zinc-500" />
          <span className="label-xs">Active Agents</span>
        </div>
        <span className="font-mono text-xs text-zinc-600">
          {agents.filter(a => a.status === 'running').length} running
        </span>
      </div>
      <div className="flex-1 overflow-y-auto p-2">
        {agents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-4">
            <Cpu size={18} className="text-zinc-700 mb-2" />
            <p className="text-xs text-zinc-600 font-mono">No active agents</p>
          </div>
        ) : (
          agents.map((agent, i) => (
            <div key={agent.task_id || i}
              className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-zinc-800/40 transition-colors">
              <span className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${statusDots[agent.status] || 'bg-zinc-500'}`} />
              <div className="flex-1 min-w-0">
                <div className="font-mono text-xs font-medium text-zinc-300">{agent.agent_type || agent.agent_class}</div>
                {agent.phase && <div className="text-xs text-zinc-600 truncate">{agent.phase}</div>}
              </div>
              <span className={`font-mono text-xs ${statusColors[agent.status] || 'text-zinc-500'}`}>
                {agent.status?.toUpperCase()}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
