import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import {
  Shield, AlertTriangle, FileText, Users, ArrowRight,
  Activity, Ban, Eye, Layers, RefreshCw, Server, ChevronDown,
  TrendingUp, Package,
} from 'lucide-react'
import { getDashboardStats, getCustomers } from '../api/client'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import type { DashboardStats, Customer, RiskHeatmapEntry } from '../types'

/* ── Helpers ─────────────────────────────────────────────── */

const TYPE_LABELS: Record<string, string> = {
  duplicate_rule: 'Duplicate Rules', shadowed_rule: 'Shadowed Rules',
  disabled_rule: 'Disabled Rules',   zero_hit_rule: 'Zero-Hit Rules',
  low_usage_rule: 'Low Usage',       overly_permissive: 'Overly Permissive',
  risky_service: 'Risky Services',   no_logging: 'No Logging',
  temporary_rule: 'Temporary Rules', unused_object: 'Unused Objects',
  duplicate_object: 'Duplicate Objects',
}

function riskColor(score: number) {
  if (score >= 70) return 'bg-red-500'
  if (score >= 45) return 'bg-amber-400'
  if (score >= 20) return 'bg-yellow-300'
  return 'bg-emerald-400'
}
function riskLabel(score: number) {
  if (score >= 70) return 'Critical'
  if (score >= 45) return 'High'
  if (score >= 20) return 'Medium'
  return 'Low'
}
function riskBadgeClass(score: number) {
  if (score >= 70) return 'bg-red-100 text-red-700'
  if (score >= 45) return 'bg-amber-100 text-amber-700'
  if (score >= 20) return 'bg-yellow-100 text-yellow-700'
  return 'bg-emerald-100 text-emerald-700'
}

/* ── Stat tile ───────────────────────────────────────────── */
function StatTile({
  value, label, sub, to, accent = false,
}: { value: number | string; label: string; sub?: string; to?: string; accent?: boolean }) {
  const inner = (
    <div className={`rounded-lg p-3.5 border transition-all ${
      to ? 'cursor-pointer hover:border-gray-300 hover:bg-gray-50' : ''
    } ${accent ? 'bg-gray-900 border-gray-900 text-white' : 'bg-white border-gray-200'}`}>
      <p className={`text-2xl font-bold leading-none ${accent ? 'text-white' : 'text-gray-900'}`}>{value}</p>
      <p className={`text-[11px] font-semibold uppercase tracking-wider mt-1.5 ${accent ? 'text-gray-400' : 'text-gray-400'}`}>{label}</p>
      {sub && <p className="text-[10px] text-gray-400 mt-0.5">{sub}</p>}
    </div>
  )
  return to ? <Link to={to}>{inner}</Link> : <>{inner}</>
}

/* ── Cleanup row ─────────────────────────────────────────── */
function CleanupRow({ icon: Icon, label, count, max, to }: {
  icon: React.ElementType; label: string; count: number; max: number; to: string
}) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0
  return (
    <Link to={to} className="flex items-center gap-3 py-2 px-2 rounded-lg hover:bg-gray-50 group transition-colors">
      <Icon className="w-3.5 h-3.5 text-gray-400 flex-shrink-0 group-hover:text-gray-600" />
      <span className="flex-1 text-sm text-gray-600 group-hover:text-gray-900 truncate">{label}</span>
      <div className="w-28 bg-gray-100 rounded-full h-1.5 overflow-hidden flex-shrink-0">
        <div className="h-full rounded-full bg-gray-900 transition-all" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-sm font-semibold text-gray-700 w-7 text-right">{count}</span>
      <ArrowRight className="w-3 h-3 text-gray-300 group-hover:text-gray-500 flex-shrink-0" />
    </Link>
  )
}

/* ── Severity block ──────────────────────────────────────── */
function SevBlock({ severity, count, to }: { severity: string; count: number; to: string }) {
  const cfg: Record<string, string> = {
    Critical: 'bg-red-600 border-red-700 text-white',
    High: 'bg-red-50 border-red-100 text-red-700',
    Medium: 'bg-amber-50 border-amber-100 text-amber-700',
    Low: 'bg-sky-50 border-sky-100 text-sky-700',
    Informational: 'bg-slate-50 border-slate-200 text-slate-500',
  }
  return (
    <Link to={to} className={`flex flex-col items-center justify-center rounded-xl border py-3 hover:shadow-sm transition-all ${cfg[severity] || cfg.Informational}`}>
      <span className="text-2xl font-bold leading-none">{count}</span>
      <span className="text-[10px] font-semibold uppercase tracking-wider mt-1 opacity-80">{severity}</span>
    </Link>
  )
}

/* ── Risk heatmap ────────────────────────────────────────── */
function RiskHeatmap({ data, showCustomer }: { data: RiskHeatmapEntry[]; showCustomer: boolean }) {
  if (!data.length) return null
  const maxScore = Math.max(...data.map(d => d.risk_score), 1)
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-900">Policy Risk Heatmap</h2>
          <p className="text-xs text-gray-400 mt-0.5">Top {data.length} policies by risk score</p>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-gray-400">
          {[['bg-emerald-400','Low'],['bg-yellow-300','Medium'],['bg-amber-400','High'],['bg-red-500','Critical']].map(([c,l]) => (
            <span key={l} className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-sm ${c} inline-block`} /> {l}
            </span>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100">
              {['Policy', showCustomer && 'Customer', 'Vendor', 'Risk Score', 'Level', 'Rules', 'Findings', 'High', '']
                .filter(Boolean)
                .map(h => (
                  <th key={h as string} className="pb-2 pt-0 text-left text-[11px] font-semibold text-gray-400 uppercase tracking-wide pr-4">{h}</th>
                ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {data.map(e => (
              <tr key={e.policy_id} className="hover:bg-gray-50/80 group transition-colors">
                <td className="py-2.5 pr-4 font-medium text-gray-900 max-w-[180px] truncate">{e.firewall_name}</td>
                {showCustomer && <td className="py-2.5 pr-4 text-gray-400 text-xs">{e.customer_name}</td>}
                <td className="py-2.5 pr-4">
                  <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 font-medium">{e.vendor}</span>
                </td>
                <td className="py-2.5 pr-4">
                  <div className="flex items-center gap-2">
                    <div className="w-20 bg-gray-100 rounded-full h-1.5 overflow-hidden">
                      <div className={`h-full rounded-full ${riskColor(e.risk_score)}`} style={{ width: `${(e.risk_score / maxScore) * 100}%` }} />
                    </div>
                    <span className="text-xs font-semibold text-gray-700">{Math.round(e.risk_score)}</span>
                  </div>
                </td>
                <td className="py-2.5 pr-4">
                  <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${riskBadgeClass(e.risk_score)}`}>{riskLabel(e.risk_score)}</span>
                </td>
                <td className="py-2.5 pr-4 text-gray-400 text-sm">{e.rule_count ?? '—'}</td>
                <td className="py-2.5 pr-4 text-gray-600 font-medium">{e.finding_count ?? 0}</td>
                <td className="py-2.5 pr-4">
                  {(e.high_finding_count ?? 0) > 0
                    ? <span className="text-[11px] font-bold text-white bg-red-500 px-2 py-0.5 rounded-full">{e.high_finding_count}</span>
                    : <span className="text-gray-300">—</span>}
                </td>
                <td className="py-2.5 text-right">
                  <Link to={`/findings?policy_id=${e.policy_id}`}
                    className="text-[11px] text-blue-600 hover:text-blue-800 font-medium inline-flex items-center gap-1">
                    View <ArrowRight className="w-3 h-3" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── Main ────────────────────────────────────────────────── */

export function Dashboard() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { activeCustomer, setActiveCustomer } = useCustomer()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [customers, setCustomers] = useState<Customer[]>([])
  // Use global customer context; fall back to URL param for backwards compat
  const [selectedCustomer, setSelectedCustomer] = useState(
    searchParams.get('customer_id') || activeCustomer?.id || ''
  )

  useEffect(() => { getCustomers().then(setCustomers).catch(() => {}) }, [])

  useEffect(() => {
    setLoading(true)
    getDashboardStats(selectedCustomer || undefined)
      .then(setStats).catch(console.error).finally(() => setLoading(false))
  }, [selectedCustomer])

  const handleCustomerChange = (id: string) => {
    setSelectedCustomer(id)
    // Sync with global customer context
    const found = customers.find(c => c.id === id)
    if (found) setActiveCustomer({ id: found.id, name: found.name })
    else setActiveCustomer(null)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-gray-200 border-t-gray-800" />
      </div>
    )
  }
  if (!stats) return null

  const typeMap = Object.fromEntries(stats.findings_by_type.map(t => [t.type, t.count]))
  const sevMap  = Object.fromEntries(stats.findings_by_severity.map(s => [s.severity, s.count]))

  const cleanupTypes = [
    { key: 'disabled_rule',    label: 'Disabled Rules',   icon: Ban },
    { key: 'zero_hit_rule',    label: 'Zero-Hit Rules',   icon: Activity },
    { key: 'shadowed_rule',    label: 'Shadowed Rules',   icon: Layers },
    { key: 'overly_permissive',label: 'Overly Permissive',icon: Eye },
    { key: 'no_logging',       label: 'No Logging',       icon: FileText },
    { key: 'temporary_rule',   label: 'Temporary Rules',  icon: RefreshCw },
  ]
  const totalCleanup = cleanupTypes.reduce((s, t) => s + (typeMap[t.key] || 0), 0)

  const topTypeData = stats.findings_by_type
    .sort((a, b) => b.count - a.count).slice(0, 8)
    .map(t => ({ name: TYPE_LABELS[t.type] || t.type.replace(/_/g, ' '), count: t.count }))

  const disabledPct = stats.total_rules > 0
    ? ((stats.disabled_rules / stats.total_rules) * 100).toFixed(0) + '%' : '—'
  const filterBase = selectedCustomer ? `?customer_id=${selectedCustomer}` : ''
  const findingsLink = (extra: string) =>
    selectedCustomer ? `/findings?customer_id=${selectedCustomer}&${extra}` : `/findings?${extra}`
  const selectedCustomerName = customers.find(c => c.id === selectedCustomer)?.name

  if (stats.total_policies === 0) {
    return (
      <div>
        <div className="page-header">
          <div><h1 className="page-title">Dashboard</h1><p className="page-subtitle">No policies yet</p></div>
        </div>
        <div className="page-body">
          <div className="card text-center py-20">
            <Shield className="w-14 h-14 text-gray-200 mx-auto mb-4" />
            <h2 className="text-lg font-semibold text-gray-700 mb-1">No policies analyzed yet</h2>
            <p className="text-sm text-gray-400 mb-6">Upload a policy file or connect a live device to start.</p>
            <div className="flex gap-2 justify-center">
              <Link to="/customers" className="btn-primary"><Users className="w-4 h-4" />Add Customer</Link>
              <Link to="/upload" className="btn-secondary">Upload Policy</Link>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">
            {selectedCustomerName
              ? <><span className="font-medium text-gray-600">{selectedCustomerName}</span> — customer view</>
              : 'Policy analysis across all customers'}
          </p>
        </div>
        <div className="flex gap-2 items-center">
          {customers.length > 1 && (
            <div className="relative">
              <select value={selectedCustomer} onChange={e => handleCustomerChange(e.target.value)}
                className="appearance-none pl-3 pr-8 py-2 text-sm border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-gray-900/20 cursor-pointer">
                <option value="">All Customers</option>
                {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" />
            </div>
          )}
          <Link to="/upload" className="btn-secondary"><FileText className="w-3.5 h-3.5" />Upload</Link>
          <Link to="/customers" className="btn-primary"><Users className="w-3.5 h-3.5" />Customers</Link>
        </div>
      </div>

      <div className="page-body space-y-5">

        {/* ── KPI strip ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatTile value={stats.total_rules}    label="Rules"      to={`/policies${filterBase}`} />
          <StatTile value={stats.total_policies} label="Policies"   to={`/policies${filterBase}`} />
          <StatTile value={stats.total_customers} label="Customers" to="/customers" />
          <StatTile value={stats.enabled_rules}  label="Enabled"    sub={`${stats.total_rules - stats.disabled_rules} active`} />
          <StatTile value={stats.disabled_rules} label="Disabled"   sub={disabledPct} />
          <StatTile value={stats.total_findings} label="Findings"   to={`/findings${filterBase}`} accent />
        </div>

        {/* ── Exposure posture ── */}
        {stats.exposure_summary && stats.exposure_summary.total > 0 && (
          <div className="card border-red-200 bg-red-50/40">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-600" />
                <h2 className="text-sm font-semibold text-gray-900">Exposure Posture</h2>
              </div>
              <span className="text-xs font-semibold text-red-700">
                {stats.exposure_summary.total} exposure finding{stats.exposure_summary.total !== 1 ? 's' : ''}
              </span>
            </div>
            <p className="text-xs text-gray-500 mb-3">
              Sensitive services reachable from untrusted networks, or unencrypted protocols in use. Review urgently.
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {stats.exposure_summary.by_type.map(e => (
                <Link
                  key={e.type}
                  to={findingsLink(`finding_type=${e.type}`)}
                  className="flex flex-col items-start rounded-xl border border-red-200 bg-white px-3 py-2.5 hover:shadow-sm hover:border-red-300 transition-all"
                >
                  <span className="text-2xl font-bold leading-none text-red-700">{e.count}</span>
                  <span className="mt-1 text-xs font-semibold text-gray-600">{e.label}</span>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* ── Three-panel row ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Rules for cleanup */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-900">Rules for Cleanup</h2>
              <span className="text-xs text-gray-400">{totalCleanup} items</span>
            </div>
            <div className="space-y-0.5">
              {cleanupTypes.map(({ key, label, icon }) => (
                <CleanupRow key={key} icon={icon} label={label}
                  count={typeMap[key] || 0} max={Math.max(totalCleanup, 1)}
                  to={findingsLink(`finding_type=${key}`)} />
              ))}
            </div>
          </div>

          {/* Findings by severity */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-900">Findings by Severity</h2>
              <Link to={`/findings${filterBase}`} className="text-xs text-blue-600 hover:text-blue-800 font-medium">View all</Link>
            </div>
            <div className="grid grid-cols-2 gap-2 mb-4">
              {['Critical','High','Medium','Low','Informational'].map(sev => (
                <SevBlock key={sev} severity={sev} count={sevMap[sev] || 0}
                  to={findingsLink(`severity=${sev}`)} />
              ))}
            </div>
            <div className="border-t border-gray-100 pt-3">
              <p className="text-xs text-gray-400 mb-2 font-medium">High-risk policies</p>
              {stats.top_customers_by_risk.slice(0,3).map(c => (
                <div key={c.id} className="flex items-center justify-between py-1">
                  <span className="text-xs text-gray-600 truncate flex-1">{c.name}</span>
                  {c.high_findings > 0 && (
                    <span className="text-[11px] font-bold text-red-600 ml-2">{c.high_findings} high</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Vendor / policy distribution */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-900">Vendor Distribution</h2>
              <span className="text-xs text-gray-400">{stats.total_policies} policies</span>
            </div>
            <div className="space-y-2 mb-4">
              {stats.vendor_distribution.map(({ vendor, count }) => {
                const pct = stats.total_policies > 0 ? (count / stats.total_policies) * 100 : 0
                const colors: Record<string, string> = {
                  FortiGate: 'bg-orange-500', CheckPoint: 'bg-teal-500',
                  PaloAlto: 'bg-purple-500',  CiscoASA: 'bg-blue-500',
                }
                return (
                  <div key={vendor} className="flex items-center gap-3">
                    <span className="text-xs text-gray-600 w-24 truncate flex-shrink-0">{vendor}</span>
                    <div className="flex-1 bg-gray-100 rounded-full h-1.5 overflow-hidden">
                      <div className={`h-full rounded-full ${colors[vendor] || 'bg-gray-400'}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-xs font-semibold text-gray-600 w-5 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
            <div className="border-t border-gray-100 pt-3">
              <p className="text-xs text-gray-400 mb-2 font-medium">Top customers by findings</p>
              {stats.top_customers_by_risk.slice(0,4).map(c => (
                <Link key={c.id} to={`/customers/${c.id}/findings`}
                  className="flex items-center justify-between py-1 group">
                  <span className="text-xs text-gray-600 group-hover:text-gray-900 truncate flex-1">{c.name}</span>
                  <span className="text-xs text-gray-400 ml-2">{c.total_findings}</span>
                </Link>
              ))}
            </div>
          </div>
        </div>

        {/* ── Bar chart + Heatmap ── */}
        {topTypeData.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            <div className="card lg:col-span-2">
              <h2 className="text-sm font-semibold text-gray-900 mb-4">Findings by Type</h2>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={topTypeData} layout="vertical" margin={{ left: 0, right: 16 }}>
                  <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={130}
                    tick={{ fontSize: 11, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e5e7eb', boxShadow: '0 4px 6px -1px rgba(0,0,0,.1)' }}
                    cursor={{ fill: '#f9fafb' }}
                  />
                  <Bar dataKey="count" fill="#111827" radius={[0, 4, 4, 0]}>
                    {topTypeData.map((_, i) => (
                      <Cell key={i} fill={i === 0 ? '#111827' : i === 1 ? '#374151' : '#6b7280'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="lg:col-span-3">
              <RiskHeatmap data={stats.risk_heatmap} showCustomer={!selectedCustomer} />
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
