import { type ReactNode, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { clsx } from 'clsx'

interface Props {
  open: boolean
  onClose: () => void
  title: ReactNode
  subtitle?: ReactNode
  badges?: ReactNode
  width?: 'md' | 'lg' | 'xl'
  children: ReactNode
  footer?: ReactNode
}

const WIDTHS = { md: 'w-[460px]', lg: 'w-[600px]', xl: 'w-[760px]' }

/** Right-side detail drawer — consistent shell for finding / rule / object /
 *  exposure / device detail across the app. Renders to a portal. */
export function DetailDrawer({ open, onClose, title, subtitle, badges, width = 'lg', children, footer }: Props) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="pi-drawer-overlay" onClick={onClose} />
      <div
        className={clsx('pi-drawer-panel', WIDTHS[width])}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="pi-drawer-header flex items-start justify-between gap-3 px-5 py-4 border-b">
          <div className="min-w-0">
            <h2 className="text-[15px] font-semibold text-ink-900 leading-snug">{title}</h2>
            {subtitle && <p className="text-xs text-ink-500 mt-0.5">{subtitle}</p>}
            {badges && <div className="flex flex-wrap items-center gap-1.5 mt-2">{badges}</div>}
          </div>
          <button onClick={onClose} className="shrink-0 w-8 h-8 rounded-lg text-ink-400 hover:text-ink-700 hover:bg-ink-100 flex items-center justify-center transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">{children}</div>
        {/* Footer */}
        {footer && <div className="pi-drawer-footer border-t px-5 py-3">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

/** Labeled section block for drawer bodies. */
export function DrawerSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h4 className="text-[10px] font-bold text-ink-400 uppercase tracking-[0.14em] mb-1.5">{title}</h4>
      {children}
    </div>
  )
}
