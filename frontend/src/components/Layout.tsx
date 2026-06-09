import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { clsx } from 'clsx'
import {
  LayoutDashboard, Users, Upload, List, AlertTriangle,
  Package, FileText, Settings, Shield, Server, TrendingUp,
  Activity, ChevronRight, Eye, CheckSquare, X, Building2,
} from 'lucide-react'
import { getCustomer } from '../api/client'

/* ── Nav definitions ─────────────────────────────────────────── */

const globalNav = [
  { to: '/',            label: 'Dashboard',   icon: LayoutDashboard, exact: true },
  { to: '/customers',   label: 'Customers',   icon: Users },
  { to: '/policies',    label: 'Policies',    icon: List },
  { to: '/findings',    label: 'Findings',    icon: AlertTriangle },
  { to: '/compliance',  label: 'Compliance',  icon: CheckSquare },
  { to: '/scorecard',   label: 'Scorecard',   icon: TrendingUp },
  { to: '/health',      label: 'Health',      icon: Activity },
  { to: '/reports',     label: 'Reports',     icon: FileText },
  { to: '/upload',      label: 'Upload',      icon: Upload },
  { to: '/settings',    label: 'Settings',    icon: Settings },
]

/** When in customer scope, remap certain global nav links to customer-scoped equivalents. */
function scopedTo(to: string, customerId: string): string {
  const map: Record<string, string> = {
    '/':           `/customers/${customerId}`,
    '/policies':   `/customers/${customerId}/policies`,
    '/findings':   `/customers/${customerId}/findings`,
    '/compliance': `/customers/${customerId}/compliance`,
    '/scorecard':  `/customers/${customerId}/scorecard`,
    '/health':     `/customers/${customerId}/health`,
    '/reports':    `/customers/${customerId}/reports`,
    '/upload':     `/upload?customer_id=${customerId}`,
  }
  return map[to] ?? to
}

/* ── NavItem ─────────────────────────────────────────────────── */

interface NavItemProps {
  to: string; label: string; icon: React.ElementType
  exact?: boolean; active: boolean; indent?: boolean
}

function NavItem({ to, label, icon: Icon, active, indent }: NavItemProps) {
  return (
    <Link
      to={to}
      className={clsx(
        'group flex items-center gap-2.5 py-1.5 pr-3 rounded-lg text-[13px]',
        'font-medium transition-all duration-100 relative',
        indent ? 'pl-3 ml-2' : 'pl-2.5 mx-1',
        active
          ? 'bg-white/10 text-white'
          : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
      )}
    >
      {/* Active indicator */}
      {active && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-blue-400 rounded-r" />
      )}
      <span className={clsx(
        'flex-shrink-0 w-5 h-5 flex items-center justify-center rounded transition-colors',
        active ? 'text-blue-400' : 'text-slate-500 group-hover:text-slate-300'
      )}>
        <Icon className="w-3.5 h-3.5" />
      </span>
      <span className="flex-1 truncate">{label}</span>
    </Link>
  )
}

/* ── Layout ──────────────────────────────────────────────────── */

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const customerMatch = location.pathname.match(/^\/customers\/([^/]+)/)
  const activeCustomerId = customerMatch?.[1]

  // Load customer name when in customer scope
  const [customerName, setCustomerName] = useState<string | null>(null)
  useEffect(() => {
    if (activeCustomerId) {
      getCustomer(activeCustomerId)
        .then((c: { name: string }) => setCustomerName(c.name))
        .catch(() => setCustomerName(null))
    } else {
      setCustomerName(null)
    }
  }, [activeCustomerId])

  const isActive = (to: string, exact?: boolean) => {
    if (exact) return location.pathname === to
    if (to === '/customers' && activeCustomerId) return false
    return location.pathname.startsWith(to)
  }

  /** When in customer scope, return the customer-scoped equivalent of a global nav link. */
  const effectiveTo = (to: string) =>
    activeCustomerId ? scopedTo(to, activeCustomerId) : to

  return (
    <div className="flex h-screen bg-[#f5f5f5] overflow-hidden">

      {/* ── Sidebar ───────────────────────────────────────────── */}
      <aside
        className="w-[210px] flex-shrink-0 flex flex-col"
        style={{ background: '#0f172a', boxShadow: '1px 0 0 rgba(255,255,255,0.04)' }}
      >
        {/* Brand */}
        <div className="flex items-center gap-2.5 px-4 pt-5 pb-4 mb-1">
          <div className="w-7 h-7 bg-blue-500 rounded-lg flex items-center justify-center flex-shrink-0">
            <Shield className="w-3.5 h-3.5 text-white" />
          </div>
          <div className="min-w-0">
            <p className="text-white font-semibold text-[13px] leading-tight tracking-tight">PolicyLens</p>
            <p className="text-slate-500 text-[10px] font-medium">Firewall Audit</p>
          </div>
        </div>

        {/* Customer scope banner */}
        {activeCustomerId && (
          <div className="mx-3 mb-2 rounded-lg bg-blue-500/10 border border-blue-500/20 px-2.5 py-2">
            <div className="flex items-start justify-between gap-1">
              <div className="flex items-center gap-1.5 min-w-0">
                <Building2 className="w-3 h-3 text-blue-400 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[9px] font-bold text-blue-400 uppercase tracking-widest leading-none mb-0.5">Customer Scope</p>
                  <p className="text-[11px] font-semibold text-white truncate leading-tight">
                    {customerName ?? '…'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => navigate('/customers')}
                title="Exit customer scope"
                className="flex-shrink-0 text-slate-500 hover:text-white transition-colors mt-0.5"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
            {/* Quick-access unique customer links */}
            <div className="mt-2 flex flex-col gap-0.5">
              <Link
                to={`/customers/${activeCustomerId}`}
                className={clsx(
                  'flex items-center gap-1.5 text-[11px] px-1.5 py-0.5 rounded transition-colors',
                  location.pathname === `/customers/${activeCustomerId}`
                    ? 'text-white bg-white/10'
                    : 'text-slate-400 hover:text-slate-200'
                )}
              >
                <LayoutDashboard className="w-3 h-3" /> Overview
              </Link>
              <Link
                to={`/customers/${activeCustomerId}/devices`}
                className={clsx(
                  'flex items-center gap-1.5 text-[11px] px-1.5 py-0.5 rounded transition-colors',
                  location.pathname.startsWith(`/customers/${activeCustomerId}/devices`)
                    ? 'text-white bg-white/10'
                    : 'text-slate-400 hover:text-slate-200'
                )}
              >
                <Server className="w-3 h-3" /> Live Devices
              </Link>
              <Link
                to={`/customers/${activeCustomerId}/objects`}
                className={clsx(
                  'flex items-center gap-1.5 text-[11px] px-1.5 py-0.5 rounded transition-colors',
                  location.pathname.startsWith(`/customers/${activeCustomerId}/objects`)
                    ? 'text-white bg-white/10'
                    : 'text-slate-400 hover:text-slate-200'
                )}
              >
                <Package className="w-3 h-3" /> Objects
              </Link>
            </div>
          </div>
        )}

        {/* Divider */}
        <div className="mx-3 mb-2 border-t border-white/5" />

        {/* Nav — global links, customer-scoped when in scope */}
        <nav className="flex-1 px-1 py-1 space-y-0.5 overflow-y-auto min-h-0">
          {globalNav.map(({ to, label, icon, exact }) => {
            const resolvedTo = effectiveTo(to)
            const active = exact
              ? location.pathname === resolvedTo || location.pathname === to
              : location.pathname.startsWith(resolvedTo) || (!activeCustomerId && location.pathname.startsWith(to))
            // Don't highlight /customers when in customer scope
            const reallyActive = to === '/customers' && activeCustomerId ? false : active
            return (
              <NavItem key={to} to={resolvedTo} label={label} icon={icon}
                exact={exact} active={reallyActive} />
            )
          })}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-white/5">
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-3 h-3 text-emerald-400" />
            <span className="text-[11px] text-slate-500 font-medium">Read-Only Mode</span>
          </div>
          <p className="text-slate-700 text-[10px] font-mono">v2.1.0</p>
        </div>
      </aside>

      {/* ── Main ────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto min-w-0">
        {children}
      </main>
    </div>
  )
}
