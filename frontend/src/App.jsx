import { useState, useEffect, useRef, useCallback } from 'react'
import { useWebSocket } from '../hooks/useWebSocket'
import { SessionContext } from '../context/SessionContext'
import ErrorBoundary from '../components/ErrorBoundary'
import StatusBar from '../components/StatusBar'
import ScopePanel from '../components/ScopePanel'
import DirectivesPanel from '../components/DirectivesPanel'
import TerminalPanel from '../components/TerminalPanel'
import FindingsPanel from '../components/FindingsPanel'
import AgentTracker from '../components/AgentTracker'
import PlanPanel from '../components/PlanPanel'
import HealthPanel from '../components/HealthPanel'
import ChatPane from '../components/ChatPane'

// ─── Constants ────────────────────────────────────────────────────────────────
// REST calls use relative paths — proxied by Vite to backend:8000
// WebSocket uses window.location.host so it works on any deployment
const WS_BASE = `ws://${window.location.host}`

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

  // Terminal panel state
  const [terminalLines, setTerminalLines] = useState([])
  const [terminalWsConnected, setTerminalWsConnected] = useState(false)

  // Fetch health + directives
  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch('/health')
      setHealth(await r.json())
    } catch { setHealth(null) }
  }, [])

  const fetchDirectives = useCallback(async () => {
    try {
      const r = await fetch('/directives')
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
  // NOTE: retained here for Task 1 (imports + ErrorBoundary wrapping only) —
  // Task 2 removes this handler and the chat socket call, since ChatPane now
  // owns the chat socket internally.
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

  const handleTerminalMessage = useCallback((data) => {
    setTerminalLines(prev => {
      const next = [...prev, data]
      return next.length > 2000 ? next.slice(next.length - 2000) : next
    })
  }, [])

  const { connected: terminalConnected } = useWebSocket(
    `${WS_BASE}/ws/terminal`,
    handleTerminalMessage,
  )

  useEffect(() => {
    setTerminalWsConnected(terminalConnected)
  }, [terminalConnected])

  const agentActive = agents.some(a => a.status === 'running')

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
      const r = await fetch('/scope', {
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
      await fetch(`/gate/${action}/${gateEventId}`, { method: 'POST' })
      setPendingGate(null)
    } catch (e) {
      console.error('Gate resolve failed:', e)
    }
  }, [])

  // Session state distribution (D-07/D-08) — placeholder pass-through so the tree
  // compiles; sessionId/chatConnected declarations and full useMemo wiring land in Task 2.
  const sessionValue = {
    chatConnected, eventsConnected, terminalConnected,
    scope, currentPlan, engagementActive, engagementStart,
  }

  // ── Layout ──────────────────────────────────────────────────────────────
  return (
    <SessionContext.Provider value={sessionValue}>
      <div className="flex flex-col h-screen bg-zinc-950 text-zinc-100 overflow-hidden">
        {/* Top status bar */}
        <ErrorBoundary panelName="Status Bar">
          <StatusBar
            health={health}
            wsEvents={eventsConnected}
            wsChat={chatConnected}
            engagementActive={engagementActive}
            startTime={engagementStart}
          />
        </ErrorBoundary>

        {/* Main grid */}
        <div className="flex flex-1 min-h-0 gap-2 p-2">

          {/* LEFT COLUMN — Scope + Directives */}
          <div className="flex flex-col gap-2 w-56 shrink-0">
            <div className="flex-1 min-h-0 max-h-[55%]">
              <ErrorBoundary panelName="Scope Configuration">
                <ScopePanel scope={scope} onSetScope={handleSetScope} />
              </ErrorBoundary>
            </div>
            <div className="flex-1 min-h-0">
              <ErrorBoundary panelName="Directives">
                <DirectivesPanel directives={directives} onSendDirective={handleSendDirective} />
              </ErrorBoundary>
            </div>
          </div>

          {/* CENTRE — Health (top) + Terminal + Chat (bottom) */}
          <div className="flex flex-col gap-2 flex-1 min-w-0">
            {/* Health bar */}
            <div className="shrink-0">
              <ErrorBoundary panelName="System Health">
                <HealthPanel health={health} onRefresh={fetchHealth} />
              </ErrorBoundary>
            </div>
            {/* Terminal feed — takes ~45% of centre */}
            <div style={{ flex: '0 0 42%' }} className="min-h-0">
              <ErrorBoundary panelName="Terminal">
                <TerminalPanel
                  lines={terminalLines}
                  agentActive={agentActive}
                  wsConnected={terminalWsConnected}
                />
              </ErrorBoundary>
            </div>
            {/* Chat — fills remaining */}
            <div className="flex-1 min-h-0">
              <ErrorBoundary panelName="Operator Console">
                <ChatPane
                  pendingGate={pendingGate}
                  onGateResolve={handleGateResolve}
                />
              </ErrorBoundary>
            </div>
          </div>

          {/* RIGHT COLUMN — Plan + Agents + Findings */}
          <div className="flex flex-col gap-2 w-72 shrink-0">
            <div style={{ flex: '0 0 38%' }} className="min-h-0">
              <ErrorBoundary panelName="Engagement Plan">
                <PlanPanel plan={currentPlan} />
              </ErrorBoundary>
            </div>
            <div style={{ flex: '0 0 22%' }} className="min-h-0">
              <ErrorBoundary panelName="Active Agents">
                <AgentTracker agents={agents} />
              </ErrorBoundary>
            </div>
            <div className="flex-1 min-h-0">
              <ErrorBoundary panelName="Findings">
                <FindingsPanel findings={findings} />
              </ErrorBoundary>
            </div>
          </div>

        </div>
      </div>
    </SessionContext.Provider>
  )
}
