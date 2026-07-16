import { clsx } from 'clsx'

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const severityClass: Record<string, string> = {
    Critical: 'pi-badge-critical',
    High: 'pi-badge-high',
    Medium: 'pi-badge-medium',
    Low: 'pi-badge-low',
    Informational: 'pi-badge-info',
  }
  const cls = clsx(
    'pi-badge',
    severityClass[severity] || 'pi-badge-info',
    size === 'sm' ? 'pi-badge-sm' : 'pi-badge-md',
  )
  return <span className={cls}>{severity}</span>
}

interface ConfidenceProps {
  confidence: string
  size?: 'sm' | 'md'
}

/** Confidence badge: neutral outline style so it never competes with severity. */
export function ConfidenceBadge({ confidence, size = 'sm' }: ConfidenceProps) {
  const cls = clsx(
    'pi-badge pi-confidence',
    size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5',
    {
      'pi-confidence-high': confidence === 'High',
      'pi-confidence-medium': confidence === 'Medium',
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
