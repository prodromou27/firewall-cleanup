import { cn } from '@/lib/utils'

export const VENDOR_META: Record<string, { label: string; short: string; badge: string; mark: string; accent: string }> = {
  FortiGate: {
    label: 'FortiGate',
    short: 'FG',
    badge: 'border-orange-200 bg-orange-50 text-orange-700',
    mark: 'from-orange-500 to-red-600',
    accent: 'bg-orange-500',
  },
  CheckPoint: {
    label: 'Check Point',
    short: 'CP',
    badge: 'border-teal-200 bg-teal-50 text-teal-700',
    mark: 'from-teal-500 to-emerald-700',
    accent: 'bg-teal-500',
  },
  PaloAlto: {
    label: 'Palo Alto',
    short: 'PA',
    badge: 'border-purple-200 bg-purple-50 text-purple-700',
    mark: 'from-purple-500 to-indigo-700',
    accent: 'bg-purple-500',
  },
  CiscoASA: {
    label: 'Cisco ASA',
    short: 'CA',
    badge: 'border-blue-200 bg-blue-50 text-blue-700',
    mark: 'from-blue-500 to-sky-700',
    accent: 'bg-blue-500',
  },
  HuaweiUSG: {
    label: 'Huawei USG',
    short: 'HW',
    badge: 'border-red-200 bg-red-50 text-red-700',
    mark: 'from-red-500 to-rose-700',
    accent: 'bg-red-500',
  },
}

export function vendorMeta(vendor?: string | null) {
  return VENDOR_META[vendor || ''] || {
    label: vendor || 'Unknown',
    short: (vendor || 'FW').slice(0, 2).toUpperCase(),
    badge: 'border-ink-200 bg-ink-100 text-ink-600',
    mark: 'from-slate-500 to-slate-700',
    accent: 'bg-slate-500',
  }
}

interface VendorBadgeProps {
  vendor?: string | null
  showMark?: boolean
  className?: string
}

export function VendorBadge({ vendor, showMark = false, className }: VendorBadgeProps) {
  const meta = vendorMeta(vendor)
  return (
    <span className={cn('vendor-badge', meta.badge, className)}>
      {showMark && (
        <span className={cn('vendor-mark h-4 w-4 text-[8px]', meta.mark)}>
          {meta.short}
        </span>
      )}
      {meta.label}
    </span>
  )
}

interface VendorMarkProps {
  vendor?: string | null
  className?: string
}

export function VendorMark({ vendor, className }: VendorMarkProps) {
  const meta = vendorMeta(vendor)
  return <span className={cn('vendor-mark', meta.mark, className)}>{meta.short}</span>
}
