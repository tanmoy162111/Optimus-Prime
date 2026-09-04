import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
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
  const [currentPlan, setCurrentPlan]   = useState(null)
  const [scope, setScope]           = useState(null)
  const [engagementActive, setEngagementActive] = useState(false)
  const [engagementStart, setEngagementStart]   = useState(null)
  const [pendingGate, setPendingGate] = useState(null)
  const [eventCounter, setEventCounter] = useState(0)

  // Session state — NEW this phase, owned by App.jsx (D-08), fed up from
  // ChatPane's onSessionChange/onConnectionChange callbacks. ChatPane owns
  // the chat socket internally; App.jsx never had a sessionId before, and
  // chatConnected previously came from the now-removed chat socket below.
  const [sessionId, setSessionId] = useState(null)
  const [chatConnected, setChatConnected] = useState(false)

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

  const { connected: eventsConnected } = useWebSocket(`${WS_BASE}/ws`, handleEventMessage)

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

  // Send directive from panel
  // NOTE: ChatPane now owns the chat socket and its own send path internally
  // (it has no imperative "send" prop exposed to the parent, only pendingGate/
  // onGateResolve/onSessionChange/onConnectionChange, per its 04-04 contract).
  // DirectivesPanel's chip-click UX is duplicated by ChatPane's own hint chips
  // for the 4 most common directives; the remaining directives are still visible
  // here for discovery. No callback wiring exists to forward a click into
  // ChatPane's input — out of this plan's interface contract (04-PATTERNS.md).
  const handleSendDirective = useCallback((directive) => {
    console.warn('Directive triggered from DirectivesPanel — use the chat input or its hint chips to send:', directive)
  }, [])

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

  // Session state distribution (D-07/D-08) — App.jsx remains the state owner,
  // mirroring its useState fields into a memoized context value. Every field is
  // listed individually in the dependency array (RESEARCH.md Pattern 2 pitfall:
  // never pass an inline object literal as the Provider value).
  const sessionValue = useMemo(() => ({
    sessionId, chatConnected, eventsConnected, terminalConnected,
    scope, currentPlan, engagementActive, engagementStart,
  }), [sessionId, chatConnected, eventsConnected, terminalConnected,
       scope, currentPlan, engagementActive, engagementStart])

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
                  onSessionChange={setSessionId}
                  onConnectionChange={setChatConnected}
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
