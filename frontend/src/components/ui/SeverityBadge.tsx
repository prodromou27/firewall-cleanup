import { clsx } from 'clsx'

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const cls = clsx(
    'inline-flex items-center font-semibold rounded',
    size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-2.5 py-0.5',
    {
      'bg-red-100 text-red-800': severity === 'High',
      'bg-yellow-100 text-yellow-800': severity === 'Medium',
      'bg-blue-100 text-blue-800': severity === 'Low',
      'bg-gray-100 text-gray-700': severity === 'Informational',
    }
  )
  return <span className={cls}>{severity}</span>
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
