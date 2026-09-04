import { useState } from 'react'
import { Target } from 'lucide-react'

export default function ScopePanel({ scope, onSetScope }) {
  const [targets, setTargets] = useState(scope?.targets?.join(', ') || '')
  const [excluded, setExcluded] = useState(scope?.excluded_targets?.join(', ') || '')
  const [ports, setPorts] = useState(scope?.ports === 'all' ? 'all' : (scope?.ports || []).join(', ') || 'all')
  const [stealth, setStealth] = useState(scope?.stealth_level || 'medium')
  const [frameworks, setFrameworks] = useState(scope?.compliance_frameworks?.join(', ') || '')
  const [notes, setNotes] = useState(scope?.notes || '')
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    const payload = {
      targets: targets.split(',').map(t => t.trim()).filter(Boolean),
      excluded_targets: excluded.split(',').map(t => t.trim()).filter(Boolean),
      ports: ports === 'all' ? 'all' : ports.split(',').map(p => parseInt(p.trim())).filter(Boolean),
      protocols: ['tcp', 'udp'],
      stealth_level: stealth,
      compliance_frameworks: frameworks.split(',').map(f => f.trim()).filter(Boolean),
      notes,
    }
    await onSetScope(payload)
    setSaving(false)
  }

  const hasTargets = targets.trim().length > 0

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Target size={13} className="text-zinc-500" />
          <span className="label-xs">Scope Configuration</span>
        </div>
        {hasTargets && (
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="font-mono text-xs text-emerald-400">SET</span>
          </span>
        )}
      </div>
      <div className="p-4 flex flex-col gap-3 overflow-y-auto flex-1">
        <div>
          <label className="label-xs block mb-1.5">Targets *</label>
          <textarea
            className="input-field w-full resize-none text-xs"
            rows={2}
            placeholder="192.168.1.0/24, example.com, *.target.com"
            value={targets}
            onChange={e => setTargets(e.target.value)}
          />
        </div>
        <div>
          <label className="label-xs block mb-1.5">Excluded Targets</label>
          <input
            className="input-field w-full text-xs"
            placeholder="192.168.1.1, admin.example.com"
            value={excluded}
            onChange={e => setExcluded(e.target.value)}
          />
        </div>
        <div>
          <label className="label-xs block mb-1.5">Ports</label>
          <input
            className="input-field w-full text-xs"
            placeholder="all  or  80, 443, 8080"
            value={ports}
            onChange={e => setPorts(e.target.value)}
          />
        </div>
        <div>
          <label className="label-xs block mb-1.5">Stealth Level</label>
          <select
            className="input-field w-full text-xs"
            value={stealth}
            onChange={e => setStealth(e.target.value)}
          >
            <option value="low">LOW — All tools, no rate limiting</option>
            <option value="medium">MEDIUM — Rate-limited active scanning</option>
            <option value="high">HIGH — Passive tools only</option>
          </select>
        </div>
        <div>
          <label className="label-xs block mb-1.5">Compliance Frameworks</label>
          <input
            className="input-field w-full text-xs"
            placeholder="gdpr, pci-dss, iso27001, soc2, nist-csf"
            value={frameworks}
            onChange={e => setFrameworks(e.target.value)}
          />
        </div>
        <div>
          <label className="label-xs block mb-1.5">Notes</label>
          <textarea
            className="input-field w-full resize-none text-xs"
            rows={2}
            placeholder="Engagement notes, client context..."
            value={notes}
            onChange={e => setNotes(e.target.value)}
          />
        </div>
        <button
          className="btn-primary w-full mt-1"
          onClick={handleSave}
          disabled={saving || !hasTargets}
        >
          {saving ? 'Saving...' : 'Apply Scope'}
        </button>
      </div>
    </div>
  )
}
