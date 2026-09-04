import { useState, useMemo } from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SessionContext, useSession } from './SessionContext'

// Consumer that reads fields purely via useContext (no props).
function SessionIdDisplay() {
  const session = useSession()
  return (
    <div>
      <span data-testid="session-id">{session?.sessionId ?? 'none'}</span>
      <span data-testid="chat-connected">{String(session?.chatConnected ?? false)}</span>
    </div>
  )
}

describe('SessionContext', () => {
  it('Test 1: a consumer reads provided fields via useContext without receiving them as props', () => {
    render(
      <SessionContext.Provider value={{ sessionId: 'abc-123', chatConnected: true }}>
        <SessionIdDisplay />
      </SessionContext.Provider>
    )
    expect(screen.getByTestId('session-id').textContent).toBe('abc-123')
    expect(screen.getByTestId('chat-connected').textContent).toBe('true')
  })

  it('Test 2: useSession() returns null (the createContext default) when rendered with no Provider', () => {
    render(<SessionIdDisplay />)
    expect(screen.getByTestId('session-id').textContent).toBe('none')
  })

  it('Test 3 (memoization): consumer does not re-render when host re-renders without changing any memoized field', () => {
    const consumerRenderCount = { current: 0 }

    function CountingConsumer() {
      consumerRenderCount.current += 1
      const session = useSession()
      return <div data-testid="value">{session.sessionId}</div>
    }

    // Mirrors App.jsx's D-08 pattern: useState fields wrapped in useMemo over
    // the exact D-07 field list, passed to the Provider. `children` is accepted
    // as a prop (a stable element reference created once by the test, not
    // recreated inline on every Host render) so that an unrelated Host state
    // change (the counter bump) doesn't force React to re-render the consumer
    // subtree unless the Provider's memoized value itself actually changes —
    // this is the exact guarantee RESEARCH.md Pattern 2 requires.
    function Host({ children }) {
      const [sessionId] = useState('fixed-id')
      const [chatConnected] = useState(true)
      const [eventsConnected] = useState(true)
      const [terminalConnected] = useState(false)
      const [scope] = useState(null)
      const [currentPlan] = useState(null)
      const [engagementActive] = useState(false)
      const [engagementStart] = useState(null)
      const [unrelatedCounter, setUnrelatedCounter] = useState(0)

      const sessionValue = useMemo(
        () => ({
          sessionId,
          chatConnected,
          eventsConnected,
          terminalConnected,
          scope,
          currentPlan,
          engagementActive,
          engagementStart,
        }),
        [
          sessionId,
          chatConnected,
          eventsConnected,
          terminalConnected,
          scope,
          currentPlan,
          engagementActive,
          engagementStart,
        ]
      )

      return (
        <SessionContext.Provider value={sessionValue}>
          <button onClick={() => setUnrelatedCounter((c) => c + 1)}>bump</button>
          <span data-testid="counter">{unrelatedCounter}</span>
          {children}
        </SessionContext.Provider>
      )
    }

    render(
      <Host>
        <CountingConsumer />
      </Host>
    )
    expect(consumerRenderCount.current).toBe(1)

    // Trigger an unrelated re-render of the host (counter bump) — none of the
    // memoized D-07 fields change, so the Provider value reference stays stable
    // and the (referentially-stable) children element is not recursed into.
    fireEvent.click(screen.getByText('bump'))
    expect(screen.getByTestId('counter').textContent).toBe('1')

    // Consumer render count must NOT have increased.
    expect(consumerRenderCount.current).toBe(1)
  })
})
