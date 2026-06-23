import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  message: string
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, message: '' }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      message: error.message || 'The page could not be rendered.',
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Application render error', error, info)
  }

  render() {
    if (!this.state.hasError) return this.props.children

    return (
      <div className="min-h-screen bg-canvas flex items-center justify-center p-6">
        <div className="max-w-lg w-full rounded-lg border border-red-200 bg-white shadow-card p-6">
          <p className="text-xs font-bold uppercase tracking-[0.16em] text-red-500 mb-2">
            Application Error
          </p>
          <h1 className="text-xl font-semibold text-slate-900 mb-2">
            This page could not be displayed
          </h1>
          <p className="text-sm text-slate-600 mb-4">
            PolicyInsight recovered from a rendering error. Refresh the page, or return to the dashboard.
          </p>
          <pre className="text-xs text-red-700 bg-red-50 border border-red-100 rounded p-3 mb-4 overflow-auto max-h-32">
            {this.state.message}
          </pre>
          <div className="flex gap-2">
            <button className="btn-primary" onClick={() => window.location.reload()}>
              Refresh
            </button>
            <button className="btn-secondary" onClick={() => { window.location.href = '/' }}>
              Dashboard
            </button>
          </div>
        </div>
      </div>
    )
  }
}
