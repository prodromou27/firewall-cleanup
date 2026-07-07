import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState, useRef } from 'react'
import type React from 'react'
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
// The brand-lockup chip has a white background, so use the on-light logo
// variant — logo.png has white "Policy" text and disappears on white.
import logoImg from '../assets/logo-onlight.png'

/* ── Nav definitions ─────────────────────────────────────────── */

// Grouped product navigation — only routes that actually exist (no dead links).
const navGroups: { title: string; items: { to: string; label: string; icon: React.ElementType; exact?: boolean }[] }[] = [
  {
    title: 'Overview',
    items: [
      { to: '/',         label: 'Dashboard',        icon: LayoutDashboard, exact: true },
      { to: '/posture',  label: 'Security Posture', icon: TrendingUp },
    ],
  },
  {
    title: 'Analysis',
    items: [
      { to: '/upload',         label: 'Upload',         icon: Upload },
      { to: '/policies',       label: 'Policies',       icon: List },
      { to: '/objects',        label: 'Objects',        icon: Package },
      { to: '/findings',       label: 'Findings',       icon: AlertTriangle },
      { to: '/cleanup-plan',   label: 'Cleanup Plan',   icon: ListChecks },
      { to: '/changes',        label: 'Change Watch',   icon: GitCompareArrows },
    ],
  },
  {
    title: 'Operations',
    items: [
      { to: '/devices',         label: 'Devices',         icon: Server },
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
      { to: '/reports',         label: 'Reports',         icon: FileText },
    ],
  },
  {
    title: 'Administration',
    items: [
      { to: '/customers', label: 'Customers', icon: Users },
      { to: '/settings',  label: 'Settings',  icon: Settings },
    ],
  },
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
        'group flex items-center gap-2.5 py-1.5 pr-3 rounded-md text-[13px]',
        'font-medium transition-all duration-150 relative',
        'pl-2.5 mx-1',
        active
          ? 'bg-brand-400/15 text-white shadow-[inset_0_0_0_1px_rgba(34,211,238,0.16)]'
          : muted
          ? 'text-sidebar-faint hover:text-sidebar-muted hover:bg-sidebar-hover'
          : 'text-sidebar-muted hover:text-sidebar-foreground hover:bg-sidebar-hover'
      )}
    >
      {active && (
        <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-brand-gradient" />
      )}
      <span className={clsx(
        'flex-shrink-0 w-5 h-5 flex items-center justify-center rounded transition-colors',
        active ? 'text-brand-400' : muted ? 'text-sidebar-faint group-hover:text-sidebar-muted' : 'text-sidebar-subtle group-hover:text-sidebar-foreground'
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
            ? 'bg-brand-500/15 border border-brand-500/25 hover:bg-brand-500/20'
            : 'bg-sidebar-hover border border-sidebar-border hover:bg-sidebar-active'
        )}
      >
        <Building2 className={clsx('w-3.5 h-3.5 flex-shrink-0', activeCustomer ? 'text-brand-400' : 'text-sidebar-subtle')} />
        <div className="flex-1 min-w-0">
          {activeCustomer ? (
            <>
              <p className="text-[9px] font-bold text-brand-400 uppercase tracking-widest leading-none mb-0.5">
                Active Customer
              </p>
              <p className="text-[12px] font-semibold text-white truncate leading-tight">
                {activeCustomer.name}
              </p>
            </>
          ) : (
            <p className="text-[12px] text-sidebar-muted font-medium">All Customers</p>
          )}
        </div>
        {activeCustomer ? (
          <button
            onClick={clear}
            title="Clear customer scope"
            className="flex-shrink-0 text-sidebar-subtle hover:text-severity-critical transition-colors p-0.5 rounded"
          >
            <X className="w-3 h-3" />
          </button>
        ) : (
          <ChevronDown className={clsx('w-3 h-3 flex-shrink-0 text-sidebar-subtle transition-transform', open && 'rotate-180')} />
        )}
        {!activeCustomer && (
          <span className="sr-only">open</span>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 z-50 sidebar-elevated rounded-xl shadow-2xl overflow-hidden">
          <div className="px-2.5 py-1.5 border-b border-sidebar-border">
            <p className="text-[10px] font-semibold text-sidebar-muted uppercase tracking-wider">Select Customer</p>
          </div>
          <div className="max-h-56 overflow-y-auto">
            {loading ? (
              <div className="flex justify-center py-4">
                <div className="w-4 h-4 border-b-2 border-brand-400 rounded-full animate-spin" />
              </div>
            ) : customers.length === 0 ? (
              <p className="text-xs text-sidebar-subtle px-3 py-3 text-center">No customers found</p>
            ) : (
              <>
                <button
                  onClick={() => { setActiveCustomer(null); setOpen(false); navigate('/') }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-sidebar-hover transition-colors text-sidebar-muted hover:text-sidebar-foreground text-[12px]"
                >
                  <span className="text-sidebar-faint text-[10px]">-</span>
                  <span>All Customers</span>
                </button>
                {customers.map(c => (
                  <button
                    key={c.id}
                    onClick={() => select(c)}
                    className={clsx(
                      'w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-sidebar-hover transition-colors text-[12px]',
                      activeCustomer?.id === c.id ? 'text-brand-300 bg-brand-500/10' : 'text-sidebar-muted hover:text-sidebar-foreground'
                    )}
                  >
                    <div className="w-5 h-5 rounded-md bg-brand-gradient flex items-center justify-center flex-shrink-0">
                      <span className="text-white font-bold text-[8px]">{c.name.slice(0, 2).toUpperCase()}</span>
                    </div>
                    <span className="flex-1 truncate font-medium">{c.name}</span>
                    {c.high_findings > 0 && (
                      <span className="flex-shrink-0 bg-severity-critical/20 text-severity-critical text-[9px] font-bold px-1 py-px rounded">
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
    <div className="px-2.5 py-2.5 sidebar-divider">
      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded-md bg-brand-gradient flex items-center justify-center flex-shrink-0 shadow-soft">
          <span className="text-white font-bold text-[10px]">{initials}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-semibold text-white truncate leading-tight">{name}</p>
          <p className="text-[10px] text-sidebar-subtle truncate">{ROLE_LABELS[user.role] || user.role}</p>
        </div>
        <button
          onClick={() => { void logout() }}
          title="Sign out"
          className="flex-shrink-0 text-sidebar-subtle hover:text-severity-critical transition-colors p-1 rounded"
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
      <aside className="sidebar-shell">
        {/* Brand */}
        <div className="px-3 pt-4 pb-3 mb-1">
          <div className="brand-lockup">
            <img src={logoImg} alt="PolicyInsight" className="h-7 w-auto object-contain" />
          </div>
        </div>

        {/* Global customer selector */}
        <CustomerSelector />

        {/* Divider */}
        <div className="mx-3 mb-2 sidebar-divider" />

        {/* Grouped product nav */}
        <nav className="flex-1 px-1 py-1 overflow-y-auto min-h-0">
          {navGroups.map(group => (
            <div key={group.title} className="mb-3">
              <p className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-600">{group.title}</p>
              <div className="space-y-0.5">
                {group.items.map(({ to, label, icon, exact }) => (
                  <NavItem key={to} to={to} label={label} icon={icon} exact={exact} active={isActive(to, exact)} />
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Admin-only utility links */}
        {isAdmin && (
          <div className="px-1 pb-2 space-y-0.5 sidebar-divider pt-2">
            <NavItem to="/audit" label="Audit Trail" icon={ScrollText} active={isActive('/audit')} muted />
          </div>
        )}

        {/* Footer */}
        <div className="px-4 py-3 sidebar-divider">
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-3 h-3 text-emerald-400" />
            <span className="security-mode-pill">Read-only</span>
          </div>
          <p className="text-sidebar-faint text-[10px] font-mono">v2.1.0</p>
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
