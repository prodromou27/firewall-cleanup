import { Link, useLocation } from 'react-router-dom'
import { clsx } from 'clsx'
import {
  LayoutDashboard, Users, Upload, List, AlertTriangle,
  Package, FileText, Settings, Shield, Server, TrendingUp,
  Activity, ChevronRight, Eye, CheckSquare,
} from 'lucide-react'

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

function customerNav(id: string) {
  return [
    { to: `/customers/${id}`,             label: 'Overview',    icon: LayoutDashboard, exact: true },
    { to: `/customers/${id}/devices`,     label: 'Live Devices',icon: Server },
    { to: `/customers/${id}/policies`,    label: 'Policies',    icon: List },
    { to: `/customers/${id}/findings`,    label: 'Findings',    icon: AlertTriangle },
    { to: `/customers/${id}/compliance`,  label: 'Compliance',  icon: CheckSquare },
    { to: `/customers/${id}/objects`,     label: 'Objects',     icon: Package },
    { to: `/customers/${id}/scorecard`,   label: 'Scorecard',   icon: TrendingUp },
    { to: `/customers/${id}/health`,      label: 'Health',      icon: Activity },
    { to: `/customers/${id}/reports`,     label: 'Reports',     icon: FileText },
  ]
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
  const customerMatch = location.pathname.match(/^\/customers\/([^/]+)/)
  const activeCustomerId = customerMatch?.[1]

  const isActive = (to: string, exact?: boolean) => {
    if (exact) return location.pathname === to
    // Don't let /customers match /customers/xxx/policies etc when customer scope is active
    if (to === '/customers' && activeCustomerId) return false
    return location.pathname.startsWith(to)
  }

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

        {/* Divider */}
        <div className="mx-3 mb-2 border-t border-white/5" />

        {/* Global nav */}
        <nav className="flex-1 px-1 py-1 space-y-0.5 overflow-y-auto min-h-0">
          {globalNav.map(({ to, label, icon, exact }) => (
            <NavItem key={to} to={to} label={label} icon={icon} exact={exact}
              active={isActive(to, exact)} />
          ))}

          {/* Customer-scoped nav */}
          {activeCustomerId && (
            <>
              <div className="mx-2 my-3 border-t border-white/5" />
              <p className="px-3 text-[9px] font-bold text-slate-600 uppercase tracking-widest mb-1">
                Customer Scope
              </p>
              {customerNav(activeCustomerId).map(({ to, label, icon, exact }) => (
                <NavItem key={to} to={to} label={label} icon={icon} exact={exact}
                  active={isActive(to, exact)} indent />
              ))}
            </>
          )}
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
