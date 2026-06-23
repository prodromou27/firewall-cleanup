import { clsx } from 'clsx'

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const severityClass: Record<string, string> = {
    Critical: 'badge-critical',
    High: 'badge-high',
    Medium: 'badge-medium',
    Low: 'badge-low',
    Informational: 'badge-info',
  }
  const cls = clsx(
    severityClass[severity] || 'badge-info',
    size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-2.5 py-0.5',
  )
  return <span className={cls}>{severity}</span>
}

interface ConfidenceProps {
  confidence: string
  size?: 'sm' | 'md'
}

/** Confidence badge — neutral, outline style so it never competes with severity. */
export function ConfidenceBadge({ confidence, size = 'sm' }: ConfidenceProps) {
  const cls = clsx(
    'inline-flex items-center font-medium rounded border',
    size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5',
    {
      'border-brand-300 text-brand-700 bg-brand-50': confidence === 'High',
      'border-info-300 text-info-700 bg-info-50': confidence === 'Medium',
      'border-slate-300 text-slate-500 bg-slate-50': confidence === 'Low' || !['High', 'Medium'].includes(confidence),
    }
  )
  return <span className={cls} title="Analysis confidence reflects data completeness">{confidence} confidence</span>
}

interface StatusProps {
  status: string
}

export function StatusBadge({ status }: StatusProps) {
  const statusClass: Record<string, string> = {
    'Review Required': 'status-review',
    'Approved for Cleanup': 'status-approved',
    'Cleanup Completed': 'status-completed',
    'False Positive': 'status-muted',
    'Accepted Risk': 'status-muted',
  }
  const cls = clsx(statusClass[status] || 'status-muted', 'text-xs px-2 py-0.5')
  return <span className={cls}>{status}</span>
}
