import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield, Activity, Terminal, Search, AlertTriangle,
  CheckCircle, XCircle, Clock, Wifi, WifiOff, ChevronRight,
  RefreshCw, Send, Settings, Layers, Target, Zap,
  Eye, Lock, Globe, Server, Cpu, Radio,
} from 'lucide-react'

// ─── Constants ────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS_BASE  = API_BASE.replace(/^http/, 'ws')

// ─── Utilities ────────────────────────────────────────────────────────────────
const SEVERITY_MAP = {
  critical: { label: 'CRITICAL', cls: 'severity-critical', dot: 'bg-red-400' },
  high:     { label: 'HIGH',     cls: 'severity-high',     dot: 'bg-orange-400' },
  medium:   { label: 'MEDIUM',   cls: 'severity-medium',   dot: 'bg-yellow-400' },
  low:      { label: 'LOW',      cls: 'severity-low',      dot: 'bg-blue-400' },
  info:     { label: 'INFO',     cls: 'severity-info',     dot: 'bg-zinc-500' },
}

const EVENT_ICONS = {
  ENGAGEMENT_STARTED:   { icon: Zap,           color: 'text-emerald-400' },
  ENGAGEMENT_PLANNED:   { icon: Layers,        color: 'text-sky-400' },
  ENGAGEMENT_COMPLETED: { icon: CheckCircle,   color: 'text-emerald-400' },
  PHASE_STARTED:        { icon: ChevronRight,  color: 'text-sky-400' },
  PHASE_COMPLETED:      { icon: CheckCircle,   color: 'text-emerald-300' },
  AGENT_SPAWNED:        { icon: Cpu,           color: 'text-violet-400' },
  AGENT_RUNNING:        { icon: Activity,      color: 'text-sky-300' },
  AGENT_FINISHED:       { icon: CheckCircle,   color: 'text-emerald-400' },
  AGENT_FAILED:         { icon: XCircle,       color: 'text-red-400' },
  FINDING_CREATED:      { icon: AlertTriangle, color: 'text-orange-400' },
  FINDING_VERIFIED:     { icon: Eye,           color: 'text-sky-400' },
  FINDING_CLASSIFIED:   { icon: CheckCircle,   color: 'text-emerald-400' },
  GATE_CONFIRMATION_REQUIRED: { icon: Lock,   color: 'text-amber-400' },
  GATE_AUTO_APPROVED:   { icon: CheckCircle,   color: 'text-zinc-400' },
  OPERATOR_MESSAGE:     { icon: Terminal,      color: 'text-zinc-400' },
  KALI_UNREACHABLE:     { icon: WifiOff,       color: 'text-red-400' },
  TOOL_TIMEOUT:         { icon: Clock,         color: 'text-amber-400' },
  TOKEN_BUDGET_WARNING: { icon: AlertTriangle, color: 'text-amber-400' },
  LLM_FALLBACK:         { icon: RefreshCw,     color: 'text-amber-300' },
  SYSTEM_STARTED:       { icon: Shield,        color: 'text-emerald-400' },
  CVE_CORRELATED:       { icon: Globe,         color: 'text-sky-400' },
  ATTACK_MAPPED:        { icon: Target,        color: 'text-orange-400' },
}

const REPORT_FORMATS_UI = [
  'executive', 'technical', 'remediation_roadmap',
  'developer_handoff', 'compliance_mapping', 'regression',
]
const REPORT_FRAMEWORKS = ['NIST-CSF', 'PCI-DSS', 'GDPR', 'ISO27001', 'SOC2']

const fmtTime = (iso) => {
  const d = new Date(iso || Date.now())
  return d.toLocaleTimeString('en-US', { hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit' })
}

const fmtElapsed = (start) => {
  const ms = Date.now() - new Date(start).getTime()
  if (ms < 60000) return `${Math.floor(ms/1000)}s`
  return `${Math.floor(ms/60000)}m ${Math.floor((ms%60000)/1000)}s`
}

// ─── Hooks ────────────────────────────────────────────────────────────────────
function useWebSocket(url, onMessage, enabled = true) {
  const wsRef = useRef(null)
  const [connected, setConnected] = useState(false)
  const reconnectTimer = useRef(null)
  const lastSeq = useRef(0)

  const connect = useCallback(() => {
    if (!enabled) return
    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        // Send reconnect with last seen seq
        ws.send(JSON.stringify({ type: 'reconnect', last_seq: lastSeq.current }))
      }

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.seq) lastSeq.current = data.seq
          onMessage(data)
        } catch {}
      }

      ws.onclose = () => {
        setConnected(false)
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.onerror = () => ws.close()
    } catch {}
  }, [url, onMessage, enabled])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
      return true
    }
    return false
  }, [])

  return { connected, send }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatusBar({ health, wsEvents, wsChat, engagementActive, startTime }) {
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

function ScopePanel({ scope, onSetScope }) {
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

function DirectivesPanel({ directives, onSendDirective }) {
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

function EventCard({ event, index }) {
  const meta = EVENT_ICONS[event.event_type] || { icon: Activity, color: 'text-zinc-400' }
  const Icon = meta.icon
  const isGate = event.event_type === 'GATE_CONFIRMATION_REQUIRED'
  const isFinding = event.event_type === 'FINDING_CREATED'
  const isError = event.event_type?.includes('FAILED') || event.event_type?.includes('UNREACHABLE')

  return (
    <div className={`flex gap-3 px-4 py-3 border-b border-zinc-800/60 animate-slide-up
      ${isGate ? 'bg-amber-500/5 border-l-2 border-l-amber-500/50' : ''}
      ${isFinding ? 'bg-orange-500/5 border-l-2 border-l-orange-500/50' : ''}
      ${isError ? 'bg-red-500/5 border-l-2 border-l-red-500/50' : ''}
      hover:bg-zinc-800/30 transition-colors`}
    >
      <div className="pt-0.5 shrink-0">
        <Icon size={13} className={meta.color} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="font-mono text-xs font-medium text-zinc-300">{event.event_type}</span>
          {event.channel && (
            <span className="font-mono text-xs text-zinc-600">#{event.channel}</span>
          )}
        </div>
        {event.payload && (
          <div className="text-xs text-zinc-500 font-mono leading-relaxed">
            {renderPayload(event.payload)}
          </div>
        )}
      </div>
      <div className="shrink-0 font-mono text-xs text-zinc-700 pt-0.5">
        {fmtTime(event.received_at)}
      </div>
    </div>
  )
}

function renderPayload(payload) {
  const p = payload
  const parts = []

  if (p.message) parts.push(p.message)
  else if (p.directive) parts.push(`directive: ${p.directive}`)
  if (p.phase_name) parts.push(`phase: ${p.phase_name}`)
  if (p.agent_type) parts.push(`agent: ${p.agent_type}`)
  if (p.plan_id) parts.push(`plan: ${p.plan_id.slice(0, 8)}…`)
  if (p.total_findings != null) parts.push(`findings: ${p.total_findings}`)
  if (p.findings_count) parts.push(`new findings: ${p.findings_count}`)
  if (p.status) parts.push(`status: ${p.status}`)
  if (p.tool) parts.push(`tool: ${p.tool}`)
  if (p.confirm_command) parts.push(`→ type: ${p.confirm_command}`)
  if (p.from_model) parts.push(`${p.from_model} → ${p.to_model}`)
  if (p.used != null && p.budget != null) parts.push(`${p.used.toLocaleString()}/${p.budget.toLocaleString()} tokens`)
  if (p.note) parts.push(p.note)
  if (p.error) parts.push(`⚠ ${String(p.error).slice(0, 100)}`)

  return parts.length > 0 ? parts.join('  ·  ') : JSON.stringify(p).slice(0, 120)
}

function EventFeed({ events }) {
  const bottomRef = useRef(null)
  const containerRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

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
          <Activity size={13} className="text-zinc-500" />
          <span className="label-xs">Live Event Feed</span>
          {events.length > 0 && (
            <span className="flex items-center gap-1.5 ml-1">
              <span className="dot-live" />
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-zinc-600">{events.length} events</span>
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
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <Activity size={24} className="text-zinc-700 mb-3" />
            <p className="font-mono text-xs text-zinc-600">Waiting for events...</p>
            <p className="text-xs text-zinc-700 mt-1">Set a scope and send a directive to begin</p>
          </div>
        ) : (
          events.map((ev, i) => <EventCard key={ev._id || i} event={ev} index={i} />)
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

function FindingsPanel({ findings }) {
  const [selected, setSelected] = useState(null)
  const [reportFormat, setReportFormat] = useState('executive')
  const [reportFramework, setReportFramework] = useState('NIST-CSF')
  const [downloading, setDownloading] = useState(null)
  const [reportError, setReportError] = useState(null)

  const triggerDownload = (blob, filename) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const downloadReport = async (type) => {
    setDownloading(type)
    setReportError(null)
    const filename = `report-${reportFormat}.${type}`
    const url = type === 'json'
      ? `${API_BASE}/report/${reportFormat}`
      : `${API_BASE}/report/${reportFormat}/${type}`
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: findings.length ? findings : undefined,
          framework: reportFramework,
        }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }))
        throw new Error(err.detail || resp.statusText)
      }
      triggerDownload(await resp.blob(), filename)
    } catch (e) {
      setReportError(e.message || 'Report generation failed')
    } finally {
      setDownloading(null)
    }
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sorted = [...findings].sort((a, b) =>
    (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)
  )

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <AlertTriangle size={13} className="text-zinc-500" />
          <span className="label-xs">Findings</span>
        </div>
        <div className="flex items-center gap-2">
          {['critical','high','medium','low'].map(s => counts[s] ? (
            <span key={s} className={`font-mono text-xs px-1.5 py-0.5 rounded border ${SEVERITY_MAP[s].cls}`}>
              {counts[s]} {s.slice(0,1).toUpperCase()}
            </span>
          ) : null)}
          {findings.length === 0 && <span className="font-mono text-xs text-zinc-600">none</span>}
        </div>
      </div>

      {/* Report download toolbar — only shown when findings exist */}
      {findings.length > 0 && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-zinc-800 shrink-0 flex-wrap">
          <select
            value={reportFormat}
            onChange={e => setReportFormat(e.target.value)}
            className="input-field text-xs h-6 py-0 px-1.5"
          >
            {REPORT_FORMATS_UI.map(f => (
              <option key={f} value={f}>{f.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <select
            value={reportFramework}
            onChange={e => setReportFramework(e.target.value)}
            className="input-field text-xs h-6 py-0 px-1.5"
          >
            {REPORT_FRAMEWORKS.map(fw => (
              <option key={fw} value={fw}>{fw}</option>
            ))}
          </select>
          <div className="flex gap-1 ml-auto">
            {['json', 'html', 'pdf'].map(type => (
              <button
                key={type}
                onClick={() => downloadReport(type)}
                disabled={downloading !== null}
                className="font-mono text-xs px-2 h-6 border border-zinc-700 rounded hover:border-zinc-500 hover:text-zinc-200 text-zinc-400 transition-colors disabled:opacity-40"
              >
                {downloading === type ? '…' : `↓ ${type.toUpperCase()}`}
              </button>
            ))}
          </div>
          {reportError && (
            <span className="font-mono text-xs text-red-400 w-full truncate">{reportError}</span>
          )}
        </div>
      )}

      <div className="flex flex-1 min-h-0">
        {/* Finding list */}
        <div className="w-full border-r border-zinc-800 overflow-y-auto">
          {sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-4">
              <CheckCircle size={20} className="text-zinc-700 mb-2" />
              <p className="text-xs text-zinc-600 font-mono">No findings yet</p>
            </div>
          ) : (
            sorted.map((f, i) => {
              const sev = SEVERITY_MAP[f.severity] || SEVERITY_MAP.info
              return (
                <button
                  key={f.finding_id || i}
                  onClick={() => setSelected(selected?.finding_id === f.finding_id ? null : f)}
                  className={`w-full text-left flex items-start gap-3 px-3 py-2.5 border-b border-zinc-800/60
                    hover:bg-zinc-800/40 transition-colors
                    ${selected?.finding_id === f.finding_id ? 'bg-zinc-800/60' : ''}`}
                >
                  <span className={`inline-block w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${sev.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-xs font-medium px-1 rounded border ${sev.cls}`}>
                        {sev.label}
                      </span>
                      <span className={`font-mono text-xs px-1.5 py-0.5 rounded border text-zinc-400 border-zinc-700 ${
                        f.classification === 'confirmed' ? 'text-emerald-400 border-emerald-500/40' :
                        f.classification === 'false_positive' ? 'text-zinc-500' :
                        f.classification === 'manual_review' ? 'text-amber-400 border-amber-500/40' : ''
                      }`}>
                        {f.classification?.toUpperCase() || 'UNVERIFIED'}
                      </span>
                    </div>
                    <div className="text-xs text-zinc-300 mt-1 leading-snug font-medium">{f.title}</div>
                    <div className="flex items-center gap-3 mt-0.5">
                      {f.target && <span className="font-mono text-xs text-zinc-600">{f.target}{f.port ? `:${f.port}` : ''}</span>}
                      {f.tool && <span className="font-mono text-xs text-zinc-600">via {f.tool}</span>}
                    </div>
                    {/* Expanded detail */}
                    {selected?.finding_id === f.finding_id && (
                      <div className="mt-3 p-3 bg-zinc-800/60 rounded border border-zinc-700 text-left animate-fade-in">
                        {f.description && (
                          <p className="text-xs text-zinc-300 leading-relaxed mb-2">{f.description}</p>
                        )}
                        {f.evidence && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">Evidence</span>
                            <pre className="text-xs text-zinc-400 font-mono whitespace-pre-wrap break-all">{f.evidence}</pre>
                          </div>
                        )}
                        {f.cve_ids?.length > 0 && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">CVEs</span>
                            <div className="flex flex-wrap gap-1">
                              {f.cve_ids.map(c => (
                                <span key={c} className="font-mono text-xs px-2 py-0.5 bg-zinc-900 border border-zinc-700 rounded text-sky-400">{c}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {f.attack_techniques?.length > 0 && (
                          <div className="mb-2">
                            <span className="label-xs block mb-1">ATT&CK Techniques</span>
                            <div className="flex flex-wrap gap-1">
                              {f.attack_techniques.map(t => (
                                <span key={t} className="font-mono text-xs px-2 py-0.5 bg-zinc-900 border border-zinc-700 rounded text-orange-400">{t}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {f.remediation && (
                          <div>
                            <span className="label-xs block mb-1">Remediation</span>
                            <p className="text-xs text-zinc-400 leading-relaxed">{f.remediation}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}

function AgentTracker({ agents }) {
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

function PlanPanel({ plan }) {
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

function ChatPanel({ messages, onSend, connected, pendingGate, onGateResolve }) {
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const bottomRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = async () => {
    const text = input.trim()
    if (!text || sending || !connected) return
    setSending(true)
    setInput('')
    onSend(text)
    setTimeout(() => setSending(false), 300)
    inputRef.current?.focus()
  }

  const handleKey = (e) => {
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
          {connected ? (
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
              onClick={() => onGateResolve && onGateResolve(pendingGate.gate_event_id, 'confirm')}
              className="font-mono text-xs px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/30 transition-colors"
            >
              confirm
            </button>
            <button
              onClick={() => onGateResolve && onGateResolve(pendingGate.gate_event_id, 'skip')}
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
          placeholder={connected ? 'Type a directive or message...' : 'Reconnecting...'}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          disabled={!connected}
        />
        <button
          className="btn-primary px-3 shrink-0"
          onClick={handleSend}
          disabled={!input.trim() || !connected || sending}
        >
          <Send size={14} />
        </button>
      </div>
    </div>
  )
}

function ChatMessage({ msg }) {
  const isUser = msg.role === 'user'
  const isError = msg.type === 'error'
  const isPlan  = msg.type === 'plan'

  return (
    <div className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'} animate-fade-in`}>
      {!isUser && (
        <div className="w-6 h-6 rounded-md bg-zinc-800 border border-zinc-700 flex items-center justify-center shrink-0 mt-0.5">
          <Shield size={12} className="text-zinc-400" />
        </div>
      )}
      <div className={`max-w-[85%] rounded-xl px-4 py-3 text-sm leading-relaxed
        ${isUser
          ? 'bg-white text-zinc-950 font-medium rounded-br-sm'
          : isError
            ? 'bg-red-500/10 border border-red-500/30 text-red-300 rounded-bl-sm'
            : isPlan
              ? 'bg-sky-500/10 border border-sky-500/30 text-zinc-200 rounded-bl-sm'
              : 'bg-zinc-800 border border-zinc-700 text-zinc-200 rounded-bl-sm'
        }`}
      >
        {isUser ? (
          <span className="font-mono">{msg.content}</span>
        ) : (
          <div>
            {isPlan && (
              <div className="flex items-center gap-2 mb-2 pb-2 border-b border-sky-500/20">
                <Layers size={12} className="text-sky-400" />
                <span className="font-mono text-xs text-sky-400 font-semibold">ENGAGEMENT PLAN CREATED</span>
              </div>
            )}
            <pre className="font-mono text-xs whitespace-pre-wrap break-words leading-relaxed">
              {msg.content}
            </pre>
            {msg.metadata?.tokens && (
              <span className="font-mono text-xs text-zinc-600 mt-2 block">
                {msg.metadata.tokens} tokens · {msg.metadata.model}
              </span>
            )}
          </div>
        )}
      </div>
      {isUser && (
        <div className="w-6 h-6 rounded-md bg-zinc-700 border border-zinc-600 flex items-center justify-center shrink-0 mt-0.5">
          <span className="font-mono text-xs text-zinc-300 font-semibold">OP</span>
        </div>
      )}
    </div>
  )
}

function HealthPanel({ health, onRefresh }) {
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

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [health, setHealth]         = useState(null)
  const [directives, setDirectives] = useState({})
  const [events, setEvents]         = useState([])
  const [findings, setFindings]     = useState([])
  const [agents, setAgents]         = useState([])
  const [chatMessages, setChatMessages] = useState([])
  const [currentPlan, setCurrentPlan]   = useState(null)
  const [scope, setScope]           = useState(null)
  const [engagementActive, setEngagementActive] = useState(false)
  const [engagementStart, setEngagementStart]   = useState(null)
  const [pendingGate, setPendingGate] = useState(null)
  const [eventCounter, setEventCounter] = useState(0)

  // Fetch health + directives
  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/health`)
      setHealth(await r.json())
    } catch { setHealth(null) }
  }, [])

  const fetchDirectives = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/directives`)
      const d = await r.json()
      setDirectives(d.directives || {})
    } catch {}
  }, [])

  useEffect(() => {
    fetchHealth()
    fetchDirectives()
    const t = setInterval(fetchHealth, 15000)
    return () => clearInterval(t)
  }, [fetchHealth, fetchDirectives])

  // Event WebSocket handler
  const handleEventMessage = useCallback((data) => {
    const event = { ...data, received_at: new Date().toISOString(), _id: `ev-${Date.now()}-${Math.random()}` }
    setEvents(prev => [...prev.slice(-499), event]) // Keep last 500

    const { event_type, payload } = data

    // Extract findings
    if (event_type === 'FINDING_CREATED' && payload) {
      const finding = payload.finding || payload
      if (finding.finding_id || finding.title) {
        setFindings(prev => {
          const exists = prev.some(f => f.finding_id === finding.finding_id)
          return exists ? prev : [...prev, finding]
        })
      }
    }

    // Track engagement state
    if (event_type === 'ENGAGEMENT_STARTED') {
      setEngagementActive(true)
      setEngagementStart(new Date().toISOString())
      setAgents([])
    }
    if (event_type === 'ENGAGEMENT_COMPLETED') {
      setEngagementActive(false)
    }

    // Track agents
    if (event_type === 'AGENT_SPAWNED' && payload) {
      setAgents(prev => {
        const exists = prev.some(a => a.task_id === payload.task_id)
        if (exists) return prev
        return [...prev, { ...payload, status: 'spawning' }]
      })
    }
    if (event_type === 'AGENT_RUNNING' && payload?.task_id) {
      setAgents(prev => prev.map(a => a.task_id === payload.task_id ? { ...a, status: 'running' } : a))
    }
    if (event_type === 'AGENT_FINISHED' && payload?.task_id) {
      setAgents(prev => prev.map(a => a.task_id === payload.task_id ? { ...a, status: 'finished' } : a))
    }
    if (event_type === 'AGENT_FAILED' && payload?.task_id) {
      setAgents(prev => prev.map(a => a.task_id === payload.task_id ? { ...a, status: 'failed' } : a))
    }

    // Track phase status in plan
    if (event_type === 'PHASE_STARTED' && payload?.phase_id) {
      setCurrentPlan(prev => {
        if (!prev) return prev
        return {
          ...prev,
          phases: prev.phases.map(p =>
            p.phase_id === payload.phase_id ? { ...p, _status: 'active' } : p
          )
        }
      })
    }
    if (event_type === 'PHASE_COMPLETED' && payload?.phase_id) {
      setCurrentPlan(prev => {
        if (!prev) return prev
        return {
          ...prev,
          phases: prev.phases.map(p =>
            p.phase_id === payload.phase_id ? { ...p, _status: 'completed' } : p
          )
        }
      })
    }

    // Gate confirmation required
    if (event_type === 'GATE_CONFIRMATION_REQUIRED') {
      setPendingGate(payload)
    }
    if (event_type === 'GATE_AUTO_APPROVED' || event_type === 'PHASE_STARTED') {
      setPendingGate(null)
    }

    setEventCounter(c => c + 1)
  }, [])

  // Chat WebSocket handler
  const handleChatMessage = useCallback((data) => {
    // Ignore control/handshake messages with no displayable content
    if (!data.content && !data.plan && data.type !== 'engagement_complete') return

    // Synthesise a human-readable message for engagement completion
    let content = data.content || ''
    if (data.type === 'engagement_complete') {
      const status = data.status === 'completed' ? '✓ Engagement complete'
        : data.status === 'partial' ? '⚠ Engagement partially complete'
        : '✗ Engagement failed'
      content = `${status} — ${data.total_findings ?? 0} finding(s)`
      if (data.errors?.length) {
        content += '\n\nErrors:\n' + data.errors.map(e => `• ${e.phase}: ${e.error}`).join('\n')
      }
    }

    setChatMessages(prev => [...prev, {
      role: 'assistant',
      type: data.type,
      content,
      metadata: data.metadata,
      plan: data.plan,
    }])

    // Store plan when received
    if (data.type === 'plan' && data.plan) {
      setCurrentPlan(data.plan)
      setFindings([])
      setAgents([])
    }
  }, [])

  const { connected: eventsConnected } = useWebSocket(`${WS_BASE}/ws`, handleEventMessage)
  const { connected: chatConnected, send: sendChat } = useWebSocket(`${WS_BASE}/chat`, handleChatMessage)

  // Send operator message
  const handleSendMessage = useCallback((text) => {
    setChatMessages(prev => [...prev, { role: 'user', content: text }])
    sendChat({ content: text })
  }, [sendChat])

  // Send directive from panel
  const handleSendDirective = useCallback((directive) => {
    handleSendMessage(directive)
  }, [handleSendMessage])

  // Set scope
  const handleSetScope = useCallback(async (scopeData) => {
    try {
      const r = await fetch(`${API_BASE}/scope`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scopeData),
      })
      if (r.ok) {
        setScope(scopeData)
        await fetchHealth()
      }
    } catch (e) {
      console.error('Set scope failed:', e)
    }
  }, [fetchHealth])

  // Resolve a human gate (confirm or skip)
  const handleGateResolve = useCallback(async (gateEventId, action) => {
    try {
      await fetch(`${API_BASE}/gate/${action}/${gateEventId}`, { method: 'POST' })
      setPendingGate(null)
    } catch (e) {
      console.error('Gate resolve failed:', e)
    }
  }, [])

  // ── Layout ──────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-screen bg-zinc-950 text-zinc-100 overflow-hidden">
      {/* Top status bar */}
      <StatusBar
        health={health}
        wsEvents={eventsConnected}
        wsChat={chatConnected}
        engagementActive={engagementActive}
        startTime={engagementStart}
      />

      {/* Main grid */}
      <div className="flex flex-1 min-h-0 gap-2 p-2">

        {/* LEFT COLUMN — Scope + Directives */}
        <div className="flex flex-col gap-2 w-56 shrink-0">
          <div className="flex-1 min-h-0 max-h-[55%]">
            <ScopePanel scope={scope} onSetScope={handleSetScope} />
          </div>
          <div className="flex-1 min-h-0">
            <DirectivesPanel directives={directives} onSendDirective={handleSendDirective} />
          </div>
        </div>

        {/* CENTRE — Event feed (top) + Chat (bottom) */}
        <div className="flex flex-col gap-2 flex-1 min-w-0">
          {/* Health bar */}
          <div className="shrink-0">
            <HealthPanel health={health} onRefresh={fetchHealth} />
          </div>
          {/* Event feed — takes ~45% of centre */}
          <div style={{ flex: '0 0 42%' }} className="min-h-0">
            <EventFeed events={events} />
          </div>
          {/* Chat — fills remaining */}
          <div className="flex-1 min-h-0">
            <ChatPanel
              messages={chatMessages}
              onSend={handleSendMessage}
              connected={chatConnected}
              pendingGate={pendingGate}
              onGateResolve={handleGateResolve}
            />
          </div>
        </div>

        {/* RIGHT COLUMN — Plan + Agents + Findings */}
        <div className="flex flex-col gap-2 w-72 shrink-0">
          <div style={{ flex: '0 0 38%' }} className="min-h-0">
            <PlanPanel plan={currentPlan} />
          </div>
          <div style={{ flex: '0 0 22%' }} className="min-h-0">
            <AgentTracker agents={agents} />
          </div>
          <div className="flex-1 min-h-0">
            <FindingsPanel findings={findings} />
          </div>
        </div>

      </div>
    </div>
  )
}
