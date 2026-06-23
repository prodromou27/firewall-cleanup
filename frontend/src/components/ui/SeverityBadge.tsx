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
