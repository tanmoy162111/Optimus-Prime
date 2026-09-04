import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import ErrorBoundary from './ErrorBoundary'

// A test component that throws during render when `shouldThrow` is true.
function Bomb({ shouldThrow }) {
  if (shouldThrow) {
    throw new Error('kaboom: sensitive internal detail')
  }
  return <div>OK child</div>
}

describe('ErrorBoundary', () => {
  it('Test 1: catches a render error and shows the fallback without propagating the throw', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <ErrorBoundary panelName="Terminal">
        <Bomb shouldThrow />
      </ErrorBoundary>
    )
    expect(screen.getByText('This panel crashed')).toBeInTheDocument()
    consoleErrorSpy.mockRestore()
  })

  it('Test 2: fault isolation — a sibling boundary keeps rendering when another boundary catches a crash', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <>
        <ErrorBoundary panelName="Terminal">
          <Bomb shouldThrow />
        </ErrorBoundary>
        <ErrorBoundary panelName="Findings">
          <div>OK sibling</div>
        </ErrorBoundary>
      </>
    )
    expect(screen.getByText('This panel crashed')).toBeInTheDocument()
    expect(screen.getByText('OK sibling')).toBeInTheDocument()
    consoleErrorSpy.mockRestore()
  })

  it('Test 3: the fallback header shows "{panelName} — Error"', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <ErrorBoundary panelName="Terminal">
        <Bomb shouldThrow />
      </ErrorBoundary>
    )
    expect(screen.getByText('Terminal — Error')).toBeInTheDocument()
    consoleErrorSpy.mockRestore()
  })

  it('Test 4: clicking "Reset panel" clears hasError and re-mounts children (non-throwing child renders)', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    let throwFlag = true
    function ControllableBomb() {
      if (throwFlag) {
        throw new Error('kaboom')
      }
      return <div>Recovered child</div>
    }

    function Wrapper() {
      return (
        <ErrorBoundary panelName="Terminal">
          <ControllableBomb />
        </ErrorBoundary>
      )
    }

    render(<Wrapper />)
    expect(screen.getByText('This panel crashed')).toBeInTheDocument()

    // Flip the flag so the next mount attempt succeeds, then click Reset.
    throwFlag = false
    fireEvent.click(screen.getByText('Reset panel'))

    expect(screen.getByText('Recovered child')).toBeInTheDocument()
    expect(screen.queryByText('This panel crashed')).not.toBeInTheDocument()

    consoleErrorSpy.mockRestore()
  })

  it('Test 5: the fallback never leaks the thrown error message/stack text', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { container } = render(
      <ErrorBoundary panelName="Terminal">
        <Bomb shouldThrow />
      </ErrorBoundary>
    )
    expect(container.textContent).not.toContain('kaboom')
    expect(container.textContent).not.toContain('sensitive internal detail')
    expect(consoleErrorSpy).toHaveBeenCalled()
    consoleErrorSpy.mockRestore()
  })
})
