import { useEffect, useState, useCallback } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import {
  AlertTriangle, Shield, FileText, RefreshCw,
  Trash2, Upload, Eye, ArrowRight, CheckCircle2, Server,
  Ban, Activity, Layers, Info, Clock, BookOpen, Database
} from 'lucide-react'
import { getCustomerStats, deletePolicy, reanalyzePolicy } from '../api/client'
import { SeverityBadge, StatusBadge } from '../components/ui/SeverityBadge'
import type { CustomerStats, PolicyRow } from '../types'
import { clsx } from 'clsx'

/* ── Helpers ─────────────────────────────────────────────── */

const TYPE_LABELS: Record<string, string> = {
  duplicate_rule: 'Duplicate Rules', shadowed_rule: 'Shadowed Rules',
  disabled_rule: 'Disabled Rules', zero_hit_rule: 'Zero-Hit Rules',
  low_usage_rule: 'Low Usage', overly_permissive: 'Overly Permissive',
  risky_service: 'Risky Services', no_logging: 'No Logging',
  temporary_rule: 'Temporary Rules', unused_object: 'Unused Objects',
  duplicate_object: 'Duplicate Objects',
}

const STATUS_ORDER = [
  'Review Required', 'Approved for Cleanup', 'Cleanup Completed',
  'False Positive', 'Accepted Risk',
]

/* ── Sub-components ──────────────────────────────────────── */

function SectionHeader({ label, color }: { label: string; color: string }) {
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-white text-xs font-bold uppercase tracking-widest mb-4 ${color}`}>
      {label}
    </div>
  )
}

function StatBlock({
  value, label, sublabel, to, color = 'blue',
}: {
  value: number | string; label: string; sublabel?: string
  to?: string; color?: string
}) {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-700', red: 'text-red-600', yellow: 'text-amber-600',
    green: 'text-green-600', gray: 'text-gray-500', orange: 'text-orange-500',
    teal: 'text-teal-600',
  }
  const inner = (
    <div className="bg-gray-50 hover:bg-blue-50 border border-gray-200 hover:border-blue-300 rounded-lg p-4 transition-all">
      <p className={`text-3xl font-extrabold ${colorMap[color] || 'text-blue-700'}`}>{value}</p>
      <p className="text-xs font-semibold text-gray-600 mt-1 uppercase tracking-wide">{label}</p>
      {sublabel && <p className="text-[11px] text-gray-400 mt-0.5">{sublabel}</p>}
    </div>
  )
  return to ? <Link to={to} className="block">{inner}</Link> : inner
}

function CleanupRow({
  icon: Icon, label, count, total, to, color,
}: {
  icon: React.ElementType; label: string; count: number; total: number; to: string; color: string
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  const colorBg: Record<string, string> = {
    red: 'bg-red-500', orange: 'bg-orange-500', yellow: 'bg-amber-500', blue: 'bg-blue-500', gray: 'bg-gray-400',
  }
  const colorText: Record<string, string> = {
    red: 'text-red-600', orange: 'text-orange-600', yellow: 'text-amber-600', blue: 'text-blue-600', gray: 'text-gray-500',
  }
  return (
    <Link to={to} className="flex items-center gap-3 py-2.5 px-3 rounded-lg hover:bg-blue-50 group transition-colors">
      <Icon className={`w-4 h-4 ${colorText[color] || 'text-blue-500'} flex-shrink-0`} />
      <span className="flex-1 text-sm text-gray-700 font-medium group-hover:text-blue-700">{label}</span>
      <div className="w-24 bg-gray-200 rounded-full h-1.5 overflow-hidden">
        <div className={`h-full rounded-full ${colorBg[color] || 'bg-blue-500'}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-sm font-bold w-5 text-right ${colorText[color] || 'text-blue-600'}`}>{count}</span>
      <ArrowRight className="w-3 h-3 text-gray-300 group-hover:text-blue-400" />
    </Link>
  )
}

function SeverityBlock({
  severity, count, to,
}: { severity: string; count: number; to: string }) {
  const cfg: Record<string, { bg: string; text: string; border: string; dot: string }> = {
    High:          { bg: 'bg-red-50',    text: 'text-red-700',    border: 'border-red-200',    dot: 'bg-red-500'   },
    Medium:        { bg: 'bg-amber-50',  text: 'text-amber-700',  border: 'border-amber-200',  dot: 'bg-amber-500' },
    Low:           { bg: 'bg-blue-50',   text: 'text-blue-700',   border: 'border-blue-200',   dot: 'bg-blue-500'  },
    Informational: { bg: 'bg-gray-50',   text: 'text-gray-500',   border: 'border-gray-200',   dot: 'bg-gray-400'  },
  }
  const c = cfg[severity] || cfg['Informational']
  return (
    <Link to={to}
      className={`flex flex-col items-center justify-center rounded-xl border px-3 py-3 hover:shadow-md transition-all ${c.bg} ${c.border} group`}>
      <span className={`text-2xl font-extrabold ${c.text}`}>{count}</span>
      <div className="flex items-center gap-1 mt-1">
        <div className={`w-2 h-2 rounded-full ${c.dot}`} />
        <span className={`text-[10px] font-bold uppercase tracking-wide ${c.text}`}>{severity}</span>
      </div>
    </Link>
  )
}

function PolicyStatusChip({ status }: { status: string }) {
  return (
    <span className={clsx('text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide', {
      'bg-yellow-100 text-yellow-700': status === 'pending' || status === 'parsing',
      'bg-blue-100 text-blue-700':   status === 'running',
      'bg-green-100 text-green-700': status === 'completed',
      'bg-red-100 text-red-700':     status === 'failed',
    })}>
      {status}
    </span>
  )
}

/* ── Main component ──────────────────────────────────────── */

export function CustomerDetail() {
  const { customerId } = useParams<{ customerId: string }>()
  const navigate = useNavigate()
  const [stats, setStats] = useState<CustomerStats | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    if (!customerId) return
    setLoading(true)
    getCustomerStats(customerId)
      .then(setStats).catch(console.error).finally(() => setLoading(false))
  }, [customerId])

  useEffect(() => { load() }, [load])

  // Auto-refresh while analysis is running
  useEffect(() => {
    if (!stats) return
    const running = stats.policies?.some(p => ['pending', 'running', 'parsing'].includes(p.analysis_status))
    if (!running) return
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [stats, load])

  const handleDelete = async (policyId: string) => {
    if (!confirm('Delete this policy and all its findings?')) return
    await deletePolicy(policyId)
    load()
  }

  const handleReanalyze = async (policyId: string) => {
    await reanalyzePolicy(policyId)
    load()
  }

  if (loading && !stats) {
    return <div className="flex justify-center items-center h-64"><div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" /></div>
  }
  if (!stats) return <div className="p-8 text-red-600">Customer not found.</div>

  const c = stats.customer

  // Pre-compute maps
  const typeMap  = Object.fromEntries(stats.findings_by_type.map(t => [t.type, t.count]))
  const sevMap   = Object.fromEntries(stats.findings_by_severity.map(s => [s.severity, s.count]))
  const statusMap = Object.fromEntries(stats.findings_by_status.map(s => [s.status, s.count]))

  const cleanupTypes = [
    { key: 'disabled_rule',     label: 'Disabled Rules',     icon: Ban,      color: 'gray'   },
    { key: 'zero_hit_rule',     label: 'Zero-Hit Rules',      icon: Activity, color: 'orange' },
    { key: 'shadowed_rule',     label: 'Shadowed Rules',      icon: Layers,   color: 'yellow' },
    { key: 'overly_permissive', label: 'Overly Permissive',   icon: Eye,      color: 'red'    },
    { key: 'no_logging',        label: 'No Logging',          icon: BookOpen, color: 'blue'   },
    { key: 'temporary_rule',    label: 'Temporary Rules',     icon: Clock,    color: 'blue'   },
    { key: 'unused_object',     label: 'Unused Objects',      icon: Database, color: 'blue'   },
  ]
  const totalCleanup = cleanupTypes.reduce((s, t) => s + (typeMap[t.key] || 0), 0)

  const typeChartData = [...stats.findings_by_type]
    .sort((a, b) => b.count - a.count).slice(0, 8)
    .map(t => ({ name: TYPE_LABELS[t.type] || t.type.replace(/_/g, ' '), count: t.count }))

  const findingsBase = `/customers/${customerId}/findings`
  const findingsLink = (type: string) => `${findingsBase}?finding_type=${type}`

  return (
    <div>
      {/* ── Header ── */}
      <div className="page-header sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-md flex-shrink-0">
            <span className="text-white font-extrabold text-base">{c.name.slice(0, 2).toUpperCase()}</span>
          </div>
          <div>
            <h1 className="page-title">{c.name}</h1>
            <p className="page-subtitle">
              {c.industry && <span className="mr-2">{c.industry}</span>}
              {c.contact_name && <span>{c.contact_name}</span>}
              {c.contact_email && <span className="ml-2">· {c.contact_email}</span>}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to={`/upload?customer_id=${customerId}`} className="btn-primary">
            <Upload className="w-4 h-4" /> Upload Policy
          </Link>
          <Link to={`/customers/${customerId}/devices`} className="btn-secondary">
            <Server className="w-4 h-4" /> Live Devices
          </Link>
          <Link to={`/customers/${customerId}/findings`} className="btn-secondary">
            <AlertTriangle className="w-4 h-4" /> Findings
          </Link>
          <Link to={`/customers/${customerId}/reports`} className="btn-secondary">
            <FileText className="w-4 h-4" /> Reports
          </Link>
        </div>
      </div>
    <div className="page-body">

      {stats.total_policies === 0 ? (
        <div className="card empty-state py-12">
          <Shield className="w-12 h-12 text-gray-200 mx-auto mb-3" />
          <h3 className="font-semibold text-gray-700 mb-2">No policies uploaded yet</h3>
          <p className="text-gray-400 text-sm mb-4">Upload a firewall policy or connect a live device to begin analysis.</p>
          <div className="flex gap-3 justify-center">
            <Link to={`/upload?customer_id=${customerId}`} className="btn-primary text-sm">Upload Policy</Link>
            <Link to={`/customers/${customerId}/devices`} className="btn-secondary text-sm">Connect Device</Link>
          </div>
        </div>
      ) : (
        <>
          {/* ── MAIN 3-PANEL ROW ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

            {/* OVERVIEW */}
            <div className="card">
              <SectionHeader label="Overview" color="bg-blue-600" />
              <div className="grid grid-cols-2 gap-3 mb-3">
                <StatBlock value={stats.total_rules}    label="Rules"    color="blue" />
                <StatBlock value={stats.total_policies} label="Policies" color="blue" />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <StatBlock value={stats.enabled_rules}  label="Enabled"  color="green" />
                <StatBlock
                  value={stats.disabled_rules}
                  label="Disabled"
                  sublabel={stats.total_rules > 0 ? ((stats.disabled_rules/stats.total_rules)*100).toFixed(1)+'%' : '0%'}
                  color="gray"
                  to={findingsLink('disabled_rule')}
                />
                <StatBlock value={stats.medium_findings ?? 0} label="Medium" color="yellow"
                  to={`${findingsBase}?severity=Medium`} />
              </div>
            </div>

            {/* RULES FOR CLEANUP */}
            <div className="card">
              <SectionHeader label="Rules for Cleanup" color="bg-orange-500" />
              <div className="flex items-center gap-3 mb-3 bg-orange-50 border border-orange-200 rounded-lg px-4 py-2.5">
                <span className="text-2xl font-extrabold text-orange-600">{totalCleanup}</span>
                <div>
                  <p className="text-xs font-bold text-orange-700 uppercase tracking-wide">Actionable Findings</p>
                  <p className="text-[11px] text-orange-400">review or remediate</p>
                </div>
              </div>
              <div className="space-y-0.5">
                {cleanupTypes.map(({ key, label, icon, color }) => (
                  <CleanupRow
                    key={key}
                    icon={icon}
                    label={label}
                    count={typeMap[key] || 0}
                    total={Math.max(totalCleanup, 1)}
                    to={findingsLink(key)}
                    color={color}
                  />
                ))}
              </div>
            </div>

            {/* FINDINGS BY SEVERITY */}
            <div className="card">
              <SectionHeader label="Findings" color="bg-red-600" />
              <div className="flex items-center gap-3 mb-4 bg-red-50 border border-red-200 rounded-lg px-4 py-2.5">
                <span className="text-2xl font-extrabold text-red-600">{stats.total_findings}</span>
                <div>
                  <p className="text-xs font-bold text-red-700 uppercase tracking-wide">Total Findings</p>
                  <p className="text-[11px] text-red-400">{sevMap['High'] || 0} high-risk</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3 mb-4">
                {(['High', 'Medium', 'Low', 'Informational'] as const).map(sev => (
                  <SeverityBlock
                    key={sev}
                    severity={sev}
                    count={sevMap[sev] || 0}
                    to={`${findingsBase}?severity=${sev}`}
                  />
                ))}
              </div>
              {/* Cleanup status */}
              <div className="border-t border-gray-100 pt-3">
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wide mb-2">Status Pipeline</p>
                <div className="space-y-1">
                  {STATUS_ORDER.map(status => (
                    <Link key={status} to={`${findingsBase}?status=${encodeURIComponent(status)}`}
                      className="flex items-center justify-between py-1 px-2 rounded hover:bg-gray-50 group">
                      <span className="text-xs text-gray-600 group-hover:text-blue-700 truncate flex-1">{status}</span>
                      <span className="text-xs font-bold text-gray-700 ml-2">{statusMap[status] || 0}</span>
                      <ArrowRight className="w-3 h-3 text-gray-200 group-hover:text-blue-400 ml-1 flex-shrink-0" />
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* ── SECOND ROW: type chart + objects ── */}
          {stats.total_findings > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <div className="card lg:col-span-2">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-gray-800">Findings by Type</h3>
                  <Link to={findingsBase} className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1">
                    All findings <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
                <div style={{ width: '100%', height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%" debounce={0}>
                    <BarChart data={typeChartData} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                      <XAxis type="number" tick={{ fontSize: 11 }} />
                      <YAxis type="category" dataKey="name" width={125} tick={{ fontSize: 11 }} />
                      <Tooltip />
                      <Bar dataKey="count" fill="#1e40af" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="card">
                <SectionHeader label="Objects" color="bg-teal-600" />
                <div className="space-y-1.5">
                  {[
                    { key: 'unused_object',    label: 'Unused Objects',    icon: Database },
                    { key: 'duplicate_object', label: 'Duplicate Objects', icon: Info },
                  ].map(({ key, label, icon: Icon }) => (
                    <Link key={key} to={findingsLink(key)}
                      className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-blue-50 group transition-colors">
                      <Icon className="w-4 h-4 text-teal-500" />
                      <span className="flex-1 text-sm text-gray-700 group-hover:text-blue-700">{label}</span>
                      <span className="text-sm font-bold text-teal-600">{typeMap[key] || 0}</span>
                      <ArrowRight className="w-3 h-3 text-gray-300 group-hover:text-blue-400" />
                    </Link>
                  ))}
                </div>
                <div className="border-t border-gray-100 mt-3 pt-3">
                  <Link to={`/customers/${customerId}/objects`}
                    className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1 font-medium">
                    All objects <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            </div>
          )}

          {/* ── POLICIES TABLE ── */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-800 flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-500" /> Firewall Policies
              </h3>
              <Link to={`/upload?customer_id=${customerId}`}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1">
                <Upload className="w-3 h-3" /> Add Policy
              </Link>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  {['Firewall', 'Vendor', 'Package', 'Uploaded', 'Rules', 'Findings', 'High', 'Status', ''].map(h => (
                    <th key={h} className="pb-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wide pr-4">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {stats.policies.map(p => (
                  <tr key={p.id} className="hover:bg-gray-50 group">
                    <td className="py-3 pr-4 font-medium text-gray-900 group-hover:text-blue-700">{p.firewall_name}</td>
                    <td className="py-3 pr-4">
                      <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded', {
                        'bg-orange-100 text-orange-700':  p.vendor === 'FortiGate',
                        'bg-sky-100 text-sky-700':        p.vendor === 'CheckPoint',
                        'bg-purple-100 text-purple-700':  p.vendor === 'PaloAlto',
                        'bg-blue-100 text-blue-700':      p.vendor === 'CiscoASA',
                        'bg-teal-100 text-teal-700':      !['FortiGate','CheckPoint','PaloAlto','CiscoASA'].includes(p.vendor),
                      })}>
                        {p.vendor}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">{p.policy_package || '—'}</td>
                    <td className="py-3 pr-4 text-gray-400 text-xs whitespace-nowrap">
                      {p.upload_date ? new Date(p.upload_date).toLocaleDateString() : '—'}
                    </td>
                    <td className="py-3 pr-4 text-gray-700">{p.rule_count}</td>
                    <td className="py-3 pr-4">
                      <Link to={`${findingsBase}?policy_id=${p.id}`}
                        className="text-gray-700 hover:text-blue-700 font-medium">{p.finding_count}</Link>
                    </td>
                    <td className="py-3 pr-4">
                      {p.high_finding_count > 0
                        ? <span className="text-xs font-bold text-white bg-red-600 px-2 py-0.5 rounded-full">{p.high_finding_count}</span>
                        : <span className="text-gray-300">0</span>}
                    </td>
                    <td className="py-3 pr-4"><PolicyStatusChip status={p.analysis_status} /></td>
                    <td className="py-3">
                      <div className="flex items-center gap-1">
                        <button onClick={() => navigate(`/policies/${p.id}/rules`)}
                          title="View rules" className="p-1.5 hover:bg-gray-100 rounded text-gray-400 hover:text-blue-600">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => handleReanalyze(p.id)}
                          title="Re-analyze" className="p-1.5 hover:bg-gray-100 rounded text-gray-400 hover:text-yellow-600">
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => handleDelete(p.id)}
                          title="Delete" className="p-1.5 hover:bg-red-50 rounded text-gray-400 hover:text-red-600">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>{/* end page-body */}
    </div>
  )
}
