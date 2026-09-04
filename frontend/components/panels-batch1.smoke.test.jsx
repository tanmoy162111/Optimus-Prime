import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import ScopePanel from './ScopePanel'
import DirectivesPanel from './DirectivesPanel'
import HealthPanel from './HealthPanel'
import PlanPanel from './PlanPanel'
import AgentTracker from './AgentTracker'

describe('panels-batch1 smoke tests', () => {
  it('ScopePanel renders without throwing', () => {
    const { container } = render(<ScopePanel scope={{}} onSetScope={() => {}} />)
    expect(container.querySelector('.panel')).toBeInTheDocument()
  })

  it('DirectivesPanel renders without throwing', () => {
    const { container } = render(<DirectivesPanel directives={{}} onSendDirective={() => {}} />)
    expect(container.querySelector('.panel')).toBeInTheDocument()
  })

  it('HealthPanel renders without throwing', () => {
    const { container } = render(<HealthPanel health={null} onRefresh={() => {}} />)
    expect(container.querySelector('.panel')).toBeInTheDocument()
  })

  it('PlanPanel renders without throwing (empty state)', () => {
    const { container } = render(<PlanPanel plan={null} />)
    expect(container.querySelector('.panel')).toBeInTheDocument()
  })

  it('AgentTracker renders without throwing', () => {
    const { container } = render(<AgentTracker agents={[]} />)
    expect(container.querySelector('.panel')).toBeInTheDocument()
  })
})
