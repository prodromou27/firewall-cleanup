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
  red: 'text-red-600 bg-red-50',
  yellow: 'text-yellow-600 bg-yellow-50',
  blue: 'text-blue-600 bg-blue-50',
  green: 'text-green-600 bg-green-50',
  gray: 'text-gray-600 bg-gray-50',
  indigo: 'text-indigo-600 bg-indigo-50',
  orange: 'text-orange-600 bg-orange-50',
}

export function StatCard({ title, value, icon, color = 'blue', subtitle }: Props) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className={clsx('mt-1 text-3xl font-bold', colorMap[color]?.split(' ')[0] ?? 'text-blue-600')}>{value}</p>
          {subtitle && <p className="mt-1 text-xs text-gray-400">{subtitle}</p>}
        </div>
        {icon && (
          <div className={clsx('p-3 rounded-full', colorMap[color])}>
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
