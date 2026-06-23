import { clsx } from 'clsx'

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const cls = clsx(
    'inline-flex items-center font-semibold rounded uppercase tracking-wide',
    size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-2.5 py-0.5',
    {
      // Critical = strongest treatment (solid burgundy)
      'bg-red-900 text-white ring-1 ring-red-950 shadow-sm': severity === 'Critical',
      // High = solid red
      'bg-red-600 text-white': severity === 'High',
      // Medium = orange, Low = amber/blue, Informational = slate (soft)
      'bg-orange-100 text-orange-700 ring-1 ring-orange-200': severity === 'Medium',
      'bg-amber-100 text-amber-700 ring-1 ring-amber-200': severity === 'Low',
      'bg-slate-100 text-slate-600 ring-1 ring-slate-200': severity === 'Informational' || !['Critical', 'High', 'Medium', 'Low'].includes(severity),
    }
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
  const cls = clsx('inline-flex items-center text-xs font-semibold rounded px-2 py-0.5', {
    'bg-orange-100 text-orange-800': status === 'Review Required',
    'bg-purple-100 text-purple-800': status === 'Approved for Cleanup',
    'bg-green-100 text-green-800': status === 'Cleanup Completed',
    'bg-gray-100 text-gray-600': status === 'False Positive',
    'bg-slate-100 text-slate-700': status === 'Accepted Risk',
  })
  return <span className={cls}>{status}</span>
}
