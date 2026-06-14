import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:pointer-events-none disabled:opacity-40 active:scale-[0.98] select-none',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground font-semibold shadow-sm hover:bg-brand-700 ring-1 ring-inset ring-white/10',
        secondary:
          'bg-white text-ink-700 border border-ink-200 shadow-card hover:bg-ink-50 hover:text-ink-900',
        ghost: 'text-ink-500 hover:bg-ink-100 hover:text-ink-900',
        destructive: 'bg-destructive text-destructive-foreground shadow-sm hover:bg-red-700',
        outline: 'border border-ink-200 bg-transparent hover:bg-ink-50 text-ink-700',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-3.5 py-2',
        sm: 'h-8 rounded-md px-2.5 text-xs',
        lg: 'h-10 rounded-lg px-5',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return (
      <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
    )
  }
)
Button.displayName = 'Button'

export { Button, buttonVariants }
