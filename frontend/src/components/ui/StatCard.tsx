import { clsx } from 'clsx'
import type { ReactNode } from 'react'

interface Props {
  title: string
  value: number | string
  icon?: ReactNode
  color?: 'red' | 'yellow' | 'blue' | 'green' | 'gray' | 'indigo' | 'orange'
  subtitle?: string
}

const colorMap = {
  red: 'text-severity-critical bg-severity-critical-soft',
  yellow: 'text-severity-medium bg-severity-medium-bg',
  blue: 'text-brand-600 bg-brand-50',
  green: 'text-success-600 bg-success-500/10',
  gray: 'text-ink-600 bg-ink-100',
  indigo: 'text-brand-700 bg-brand-50',
  orange: 'text-severity-high-fg bg-severity-high-bg',
}

export function StatCard({ title, value, icon, color = 'blue', subtitle }: Props) {
  const [valueClass, iconBgClass] = (colorMap[color] ?? colorMap.blue).split(' ')
  return (
    <div className="stat-card">
      <div className="flex items-center justify-between">
        <div>
          <p className="stat-label">{title}</p>
          <p className={clsx('stat-value', valueClass)}>{value}</p>
          {subtitle && <p className="mt-1 text-xs text-ink-400">{subtitle}</p>}
        </div>
        {icon && (
          <div className={clsx('p-3 rounded-lg', valueClass, iconBgClass)}>
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
