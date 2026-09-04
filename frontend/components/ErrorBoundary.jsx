import { Component } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default class ErrorBoundary extends Component {
  state = { hasError: false, resetKey: 0 }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    console.error(`[ErrorBoundary:${this.props.panelName}]`, error, info)
  }

  handleReset = () => {
    // Bump resetKey so the boundary's children are actually re-mounted
    // (fresh instance), not merely re-rendered with hasError cleared.
    this.setState((s) => ({ hasError: false, resetKey: s.resetKey + 1 }))
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="panel flex flex-col h-full">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <AlertTriangle size={13} className="text-red-400" />
              <span className="label-xs text-red-400">{this.props.panelName} — Error</span>
            </div>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center text-center px-4">
            <AlertTriangle size={22} className="text-red-500/60 mb-3" />
            <p className="font-mono text-xs text-red-400">This panel crashed</p>
            <p className="text-xs text-zinc-600 mt-1">An unexpected error stopped rendering. Other panels are unaffected.</p>
            <button className="btn-ghost text-xs px-2 py-1 mt-3 gap-1.5" onClick={this.handleReset}>
              <RefreshCw size={12} /> Reset panel
            </button>
          </div>
        </div>
      )
    }
    return <div key={this.state.resetKey}>{this.props.children}</div>
  }
}
