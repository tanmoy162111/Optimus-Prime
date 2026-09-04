import { Zap, Shield, Search, Globe, Cpu, Target, Lock, Server, Radio } from 'lucide-react'

export default function DirectivesPanel({ directives, onSendDirective }) {
  const icons = {
    '$pentest':        { icon: Shield,  color: 'text-red-400' },
    '$recon':          { icon: Search,  color: 'text-sky-400' },
    '$cloud-audit':    { icon: Globe,   color: 'text-violet-400' },
    '$genai-probe':    { icon: Cpu,     color: 'text-emerald-400' },
    '$scope-discover': { icon: Target,  color: 'text-orange-400' },
    '$iam-audit':      { icon: Lock,    color: 'text-amber-400' },
    '$endpoint':       { icon: Server,  color: 'text-sky-400' },
    '$ics-audit':      { icon: Radio,   color: 'text-rose-400' },
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Zap size={13} className="text-zinc-500" />
          <span className="label-xs">Directives</span>
        </div>
        <span className="font-mono text-xs text-zinc-600">{Object.keys(directives).length} available</span>
      </div>
      <div className="p-2 overflow-y-auto flex-1">
        {Object.entries(directives).map(([key, desc]) => {
          const meta = icons[key] || { icon: Zap, color: 'text-zinc-400' }
          const Icon = meta.icon
          return (
            <button
              key={key}
              onClick={() => onSendDirective(key)}
              className="w-full flex items-start gap-3 px-3 py-2.5 rounded-md
                         hover:bg-zinc-800 transition-colors duration-100 text-left group"
            >
              <Icon size={14} className={`${meta.color} mt-0.5 shrink-0`} />
              <div className="min-w-0">
                <div className="font-mono text-xs font-medium text-zinc-200 group-hover:text-white transition-colors">{key}</div>
                <div className="text-xs text-zinc-500 mt-0.5 leading-snug">{desc}</div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
