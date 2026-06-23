import { type ReactNode } from 'react'
import { Search } from 'lucide-react'
import { clsx } from 'clsx'

/** Professional filter bar shell — groups search + filter controls. */
export function FilterBar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('flex flex-wrap items-center gap-2 rounded-lg border border-ink-200 bg-white px-3 py-2.5 shadow-card', className)}>{children}</div>
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className }: {
  value: string; onChange: (v: string) => void; placeholder?: string; className?: string
}) {
  return (
    <div className={clsx('relative', className)}>
      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-400" />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full pl-8 pr-3 py-1.5 text-sm rounded-md border border-ink-200 bg-ink-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-brand-500/40 placeholder:text-ink-400"
      />
    </div>
  )
}
