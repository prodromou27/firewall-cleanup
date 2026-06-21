import { Loader2 } from 'lucide-react'
import type React from 'react'
import { cn } from '@/lib/utils'

interface LoadingStateProps {
  label?: string
  className?: string
}

export function LoadingState({ label = 'Loading data...', className }: LoadingStateProps) {
  return (
    <div className={cn('state-panel', className)}>
      <Loader2 className="w-6 h-6 text-brand-600 animate-spin" />
      <p className="text-sm font-medium text-ink-600">{label}</p>
    </div>
  )
}

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: React.ReactNode
  action?: React.ReactNode
  className?: string
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('state-panel', className)}>
      {icon && <div className="state-icon">{icon}</div>}
      <div>
        <h2 className="text-base font-semibold text-ink-800">{title}</h2>
        {description && <p className="mt-1 text-sm text-ink-400">{description}</p>}
      </div>
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

interface ErrorStateProps {
  title?: string
  message: React.ReactNode
  className?: string
}

export function ErrorState({ title = 'Something went wrong', message, className }: ErrorStateProps) {
  return (
    <div className={cn('rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700', className)}>
      <p className="font-semibold text-red-800">{title}</p>
      <div className="mt-1">{message}</div>
    </div>
  )
}
