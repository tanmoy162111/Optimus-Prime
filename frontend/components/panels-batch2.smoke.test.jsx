import { render } from '@testing-library/react'
import { describe, it, expect, beforeAll } from 'vitest'
import StatusBar from './StatusBar'
import TerminalPanel from './TerminalPanel'
import TerminalInput from './TerminalInput'
import TerminalLine from './TerminalLine'
import FindingsPanel from './FindingsPanel'

// jsdom does not implement scrollIntoView; TerminalPanel's auto-scroll effect
// (verbatim from App.jsx) calls it on mount. Polyfill for this test file only —
// component source is untouched.
beforeAll(() => {
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = () => {}
  }
})

describe('panels-batch2 smoke tests', () => {
  it('StatusBar renders without throwing given all connections down', () => {
    const { container } = render(
      <StatusBar
        health={null}
        wsEvents={false}
        wsChat={false}
        engagementActive={false}
        startTime={null}
      />
    )
    expect(container.querySelector('.label-xs')).toBeInTheDocument()
  })

  it('TerminalPanel renders without throwing given empty lines', () => {
    const { getByText } = render(
      <TerminalPanel lines={[]} agentActive={false} wsConnected={false} />
    )
    expect(getByText('Terminal')).toBeInTheDocument()
  })

  it('TerminalInput renders without throwing', () => {
    const { getByPlaceholderText } = render(<TerminalInput agentActive={false} />)
    expect(getByPlaceholderText('enter command...')).toBeInTheDocument()
  })

  it('TerminalLine renders without throwing given a minimal line', () => {
    const { container } = render(
      <TerminalLine line={{ type: 'backend_log', level: 'INFO', data: 'hello', ts: Date.now() }} />
    )
    expect(container.textContent).toContain('hello')
  })

  it('FindingsPanel renders without throwing given empty findings', () => {
    const { getByText } = render(<FindingsPanel findings={[]} />)
    expect(getByText('Findings')).toBeInTheDocument()
    expect(getByText('No findings yet')).toBeInTheDocument()
  })
})
