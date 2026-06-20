import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState, useRef } from 'react'
import { clsx } from 'clsx'
import {
  LayoutDashboard, Users, Upload, List, AlertTriangle,
  Package, FileText, Settings, Server,
  TrendingUp, Eye, ShieldAlert, Building2, ChevronDown, X, LogOut, ScrollText, ListChecks, GitCompareArrows,
} from 'lucide-react'
import { getCustomers } from '../api/client'
import { useCustomer } from '../contexts/CustomerContext'
import { useAuth } from '../contexts/AuthContext'
import type { Customer } from '../types'
import logoImg from '../assets/logo.png'

/* ── Nav definitions ─────────────────────────────────────────── */

const globalNav = [
  { to: '/',                label: 'Dashboard',       icon: LayoutDashboard, exact: true },
  { to: '/customers',       label: 'Customers',       icon: Users },
  { to: '/findings',        label: 'Findings',        icon: AlertTriangle },
  { to: '/cleanup-plan',    label: 'Cleanup Plan',    icon: ListChecks },
  { to: '/changes',         label: 'Change Watch',    icon: GitCompareArrows },
  { to: '/policies',        label: 'Policies',        icon: List },
  { to: '/posture',         label: 'Posture',         icon: TrendingUp },
  { to: '/devices',         label: 'Devices',         icon: Server },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { to: '/objects',         label: 'Objects',         icon: Package },
  { to: '/reports',         label: 'Reports',         icon: FileText },
]

const utilityNav = [
  { to: '/upload',   label: 'Upload Policy', icon: Upload },
  { to: '/settings', label: 'Settings',      icon: Settings },
]

/* ── NavItem ─────────────────────────────────────────────────── */

interface NavItemProps {
  to: string; label: string; icon: React.ElementType
  exact?: boolean; active: boolean; muted?: boolean
}

function NavItem({ to, label, icon: Icon, active, muted }: NavItemProps) {
  return (
    <Link
      to={to}
      className={clsx(
        'group flex items-center gap-2.5 py-1.5 pr-3 rounded-lg text-[13px]',
        'font-medium transition-all duration-100 relative',
        'pl-2.5 mx-1',
        active
          ? 'bg-white/10 text-white'
          : muted
          ? 'text-slate-600 hover:text-slate-400 hover:bg-white/5'
          : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
      )}
    >
      {active && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-brand-400 rounded-r" />
      )}
      <span className={clsx(
        'flex-shrink-0 w-5 h-5 flex items-center justify-center rounded transition-colors',
        active ? 'text-brand-400' : muted ? 'text-slate-600 group-hover:text-slate-400' : 'text-slate-500 group-hover:text-slate-300'
      )}>
        <Icon className="w-3.5 h-3.5" />
      </span>
      <span className="flex-1 truncate">{label}</span>
    </Link>
  )
}

/* ── Customer selector dropdown ──────────────────────────────── */

function CustomerSelector() {
  const { activeCustomer, setActiveCustomer } = useCustomer()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [customers, setCustomers] = useState<Customer[]>([])
  const [loading, setLoading] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // Load customers when dropdown opens
  useEffect(() => {
    if (!open) return
    setLoading(true)
    getCustomers().then(setCustomers).finally(() => setLoading(false))
  }, [open])

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const select = (c: Customer) => {
    setActiveCustomer({ id: c.id, name: c.name })
    setOpen(false)
    navigate('/')
  }

  const clear = (e: React.MouseEvent) => {
    e.stopPropagation()
    setActiveCustomer(null)
    navigate('/')
  }

  return (
    <div ref={ref} className="mx-2.5 mb-2 relative">
      <div
        role="button"
        tabIndex={0}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(o => !o) } }}
        className={clsx(
          'w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-all cursor-pointer',
          activeCustomer
            ? 'bg-blue-500/15 border border-blue-500/25 hover:bg-blue-500/20'
            : 'bg-white/5 border border-white/8 hover:bg-white/8'
        )}
      >
        <Building2 className={clsx('w-3.5 h-3.5 flex-shrink-0', activeCustomer ? 'text-blue-400' : 'text-slate-500')} />
        <div className="flex-1 min-w-0">
          {activeCustomer ? (
            <>
              <p className="text-[9px] font-bold text-blue-400 uppercase tracking-widest leading-none mb-0.5">
                Active Customer
              </p>
              <p className="text-[12px] font-semibold text-white truncate leading-tight">
                {activeCustomer.name}
              </p>
            </>
          ) : (
            <p className="text-[12px] text-slate-400 font-medium">All Customers</p>
          )}
        </div>
        {activeCustomer ? (
          <button
            onClick={clear}
            title="Clear customer scope"
            className="flex-shrink-0 text-slate-500 hover:text-red-400 transition-colors p-0.5 rounded"
          >
            <X className="w-3 h-3" />
          </button>
        ) : (
          <ChevronDown className={clsx('w-3 h-3 flex-shrink-0 text-slate-500 transition-transform', open && 'rotate-180')} />
        )}
        {!activeCustomer && (
          <span className="sr-only">open</span>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 z-50 bg-[#1e293b] border border-white/10 rounded-xl shadow-2xl overflow-hidden">
          <div className="px-2.5 py-1.5 border-b border-white/5">
            <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Select Customer</p>
          </div>
          <div className="max-h-56 overflow-y-auto">
            {loading ? (
              <div className="flex justify-center py-4">
                <div className="w-4 h-4 border-b-2 border-blue-400 rounded-full animate-spin" />
              </div>
            ) : customers.length === 0 ? (
              <p className="text-xs text-slate-500 px-3 py-3 text-center">No customers found</p>
            ) : (
              <>
                <button
                  onClick={() => { setActiveCustomer(null); setOpen(false); navigate('/') }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-white/5 transition-colors text-slate-400 hover:text-white text-[12px]"
                >
                  <span className="text-slate-600 text-[10px]">—</span>
                  <span>All Customers</span>
                </button>
                {customers.map(c => (
                  <button
                    key={c.id}
                    onClick={() => select(c)}
                    className={clsx(
                      'w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors text-[12px]',
                      activeCustomer?.id === c.id ? 'text-blue-300 bg-blue-500/10' : 'text-slate-300 hover:text-white'
                    )}
                  >
                    <div className="w-5 h-5 rounded-md bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center flex-shrink-0">
                      <span className="text-white font-bold text-[8px]">{c.name.slice(0, 2).toUpperCase()}</span>
                    </div>
                    <span className="flex-1 truncate font-medium">{c.name}</span>
                    {c.high_findings > 0 && (
                      <span className="flex-shrink-0 bg-red-500/20 text-red-400 text-[9px] font-bold px-1 py-px rounded">
                        {c.high_findings}H
                      </span>
                    )}
                  </button>
                ))}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Layout ──────────────────────────────────────────────────── */

const ROLE_LABELS: Record<string, string> = {
  system_admin: 'System Admin',
  tenant_admin: 'Tenant Admin',
  engineer: 'Engineer',
  reviewer: 'Reviewer',
  report_viewer: 'Report Viewer',
  read_only: 'Read-Only',
}

function UserFooter() {
  const { user, logout } = useAuth()
  if (!user) return null
  const name = user.full_name || user.email
  const initials = (user.full_name || user.email).slice(0, 2).toUpperCase()
  return (
    <div className="px-2.5 py-2.5 border-t border-white/5">
      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded-md bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center flex-shrink-0">
          <span className="text-white font-bold text-[10px]">{initials}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-semibold text-white truncate leading-tight">{name}</p>
          <p className="text-[10px] text-slate-500 truncate">{ROLE_LABELS[user.role] || user.role}</p>
        </div>
        <button
          onClick={() => { void logout() }}
          title="Sign out"
          className="flex-shrink-0 text-slate-500 hover:text-red-400 transition-colors p-1 rounded"
        >
          <LogOut className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const { user } = useAuth()
  const isAdmin = user?.role === 'system_admin' || user?.role === 'tenant_admin'

  const isActive = (to: string, exact?: boolean) => {
    if (exact) return location.pathname === to
    return location.pathname.startsWith(to)
  }

  return (
    <div className="flex h-screen bg-canvas overflow-hidden">

      {/* ── Sidebar ───────────────────────────────────────────── */}
      <aside
        className="w-[210px] flex-shrink-0 flex flex-col"
        style={{ background: '#0f172a', boxShadow: '1px 0 0 rgba(255,255,255,0.04)' }}
      >
        {/* Brand */}
        <div className="px-3 pt-4 pb-3 mb-1">
          <div className="bg-white rounded-lg px-2.5 py-1.5 inline-flex items-center">
            <img src={logoImg} alt="PolicyInsight" className="h-7 w-auto object-contain" />
          </div>
        </div>

        {/* Global customer selector */}
        <CustomerSelector />

        {/* Divider */}
        <div className="mx-3 mb-2 border-t border-white/5" />

        {/* Main nav */}
        <nav className="flex-1 px-1 py-1 space-y-0.5 overflow-y-auto min-h-0">
          {globalNav.map(({ to, label, icon, exact }) => (
            <NavItem
              key={to}
              to={to}
              label={label}
              icon={icon}
              exact={exact}
              active={isActive(to, exact)}
            />
          ))}
        </nav>

        {/* Utility links */}
        <div className="px-1 pb-2 space-y-0.5 border-t border-white/5 pt-2">
          {isAdmin && (
            <NavItem to="/audit" label="Audit Trail" icon={ScrollText} active={isActive('/audit')} muted />
          )}
          {utilityNav.map(({ to, label, icon }) => (
            <NavItem key={to} to={to} label={label} icon={icon} active={isActive(to)} muted />
          ))}
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-white/5">
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-3 h-3 text-emerald-400" />
            <span className="text-[11px] text-slate-500 font-medium">Read-Only Mode</span>
          </div>
          <p className="text-slate-700 text-[10px] font-mono">v2.1.0</p>
        </div>

        {/* Current user + sign out */}
        <UserFooter />
      </aside>

      {/* ── Main ────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto min-w-0">
        {children}
      </main>
    </div>
  )
}
