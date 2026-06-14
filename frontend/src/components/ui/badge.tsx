import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-ink-200 bg-ink-100 text-ink-600',
        outline: 'border-ink-200 text-ink-700',
        success: 'border-success-500/20 bg-success-500/10 text-success-600',
        // Severity tiers
        critical: 'border-red-700 bg-red-600 text-white shadow-sm shadow-red-600/30',
        high: 'border-red-200/80 bg-red-50 text-red-700',
        medium: 'border-amber-200/80 bg-amber-50 text-amber-700',
        low: 'border-sky-200/80 bg-sky-50 text-sky-700',
        info: 'border-ink-200 bg-ink-100 text-ink-500',
      },
    },
    defaultVariants: { variant: 'default' },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
