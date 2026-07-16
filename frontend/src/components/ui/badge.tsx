import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'pi-badge transition-colors',
  {
    variants: {
      variant: {
        default: 'pi-badge-default',
        secondary: 'pi-badge-info',
        outline: 'border-ink-200 text-ink-700',
        success: 'pi-badge-success',
        // Severity tiers
        critical: 'pi-badge-critical',
        high: 'pi-badge-high',
        medium: 'pi-badge-medium',
        low: 'pi-badge-low',
        info: 'pi-badge-info',
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
