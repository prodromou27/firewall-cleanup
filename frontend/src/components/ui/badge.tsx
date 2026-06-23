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
        critical: 'border-severity-critical-border bg-severity-critical-bg text-severity-critical-fg shadow-sm shadow-red-600/30',
        high: 'border-severity-high-border/80 bg-severity-high-bg text-severity-high-fg',
        medium: 'border-severity-medium-border/80 bg-severity-medium-bg text-severity-medium-fg',
        low: 'border-severity-low-border/80 bg-severity-low-bg text-severity-low-fg',
        info: 'border-severity-info-border bg-severity-info-bg text-severity-info-fg',
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
