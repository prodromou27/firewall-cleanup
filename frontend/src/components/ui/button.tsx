import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'pi-button focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:pointer-events-none',
  {
    variants: {
      variant: {
        default: 'pi-button-default',
        secondary: 'pi-button-secondary',
        ghost: 'pi-button-ghost',
        destructive: 'pi-button-destructive',
        outline: 'pi-button-outline',
        link: 'pi-button-link',
      },
      size: {
        default: 'pi-button-size-default',
        sm: 'pi-button-size-sm',
        lg: 'pi-button-size-lg',
        icon: 'pi-button-size-icon',
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
