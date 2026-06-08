import { useEffect, useState } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import {
  Shield, CheckCircle2, AlertTriangle, XCircle, Info,
  HelpCircle, RefreshCw, ChevronRight, Globe, Server,
  Lock, Activity, Wifi, Network, BarChart2, FileText,
  TrendingUp, Eye, EyeOff,
} from 'lucide-react'
import { getPolicies } from '../api/client'
import api from '../api/client'
import type { Policy } from '../types'
import { clsx } from 'clsx'

// ── Types ─────────────────────────────────────────────────────────────────────

interface HealthCheck {
  check_id: string
  category: string
  title: string
  status: 'pass' | 'warn' | 'fail' | 'info' | 'unknown'
  severity: string
  detail: string
  recommendation: string
  evidence: Record<string, unknown>
  requires_live_data: boolean
}

interface NatEntry {
  rule_id: string
  rule_name: string
  rule_number: number
  enabled: boolean
  sources: string[]
  destinations: string[]
  services: string[]
  nat_type: string
  nat_ip: string
  hit_count: number | null
  comments: string
}

interface ExposedService {
  service: string
  port: number | null
  risk: 'High' | 'Medium' | 'Low'
  rule_count: number
  rules: string[]
}

interface InternetRule {
  rule_id: string
  rule_name: string
  rule_number: number
  direction: string
  sources: string[]
  destinations: string[]
  services: Array<{ name: string; label: string; port: number | null; risk: string }>
  nat_enabled: boolean
  logging_enabled: boolean
  hit_count: number | null
}

interface HealthData {
  policy_id: string
  vendor: string
  firewall_name: string
  health_score: number | null
  data_coverage_pct: number
  checks: HealthCheck[]
  summary: { total: number; pass: number; warn: number; fail: number; info: number; unknown: number }
  by_category: Record<string, Record<string, number>>
  nat: {
    total_nat_rules: number
    enabled_nat_rules: number
    unused_nat_rules: NatEntry[]
    duplicate_nat_groups: Array<{ rules: string[]; count: number }>
    nat_entries: NatEntry[]
    public_exposures: unknown[]
  }
  attack_surface: {
    total_internet_rules: number
    high_risk_rules: number
    rules_without_logging: number
    internet_rules: InternetRule[]
    exposed_services: ExposedService[]
    risky_services: ExposedService[]
  }
}

// ── Status helpers ────────────────────────────────────────────────────────────

const STATUS_META = {
  pass:    { icon: CheckCircle2, color: 'text-emerald-600', bg: 'bg-emerald-50 border-emerald-100', label: 'Pass',    dot: 'bg-emerald-500' },
  warn:    { icon: AlertTriangle, color: 'text-amber-600',  bg: 'bg-amber-50 border-amber-100',     label: 'Warn',    dot: 'bg-amber-400'   },
  fail:    { icon: XCircle,       color: 'text-red-600',    bg: 'bg-red-50 border-red-100',          label: 'Fail',    dot: 'bg-red-500'     },
  info:    { icon: Info,          color: 'text-blue-600',   bg: 'bg-blue-50 border-blue-100',        label: 'Info',    dot: 'bg-blue-400'    },
  unknown: { icon: HelpCircle,    color: 'text-gray-400',   bg: 'bg-gray-50 border-gray-100',        label: 'N/A',     dot: 'bg-gray-300'    },
} as const

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  'Access Control':       Lock,
  'Authentication':       Shield,
  'Logging & Monitoring': Activity,
  'Infrastructure':       Server,
  'Security Controls':    Shield,
  'Policy Hygiene':       CheckCircle2,
  'Network Management':   Network,
}

const RISK_CHIP: Record<string, string> = {
  High:   'bg-red-100 text-red-700 border-red-200',
  Medium: 'bg-amber-100 text-amber-700 border-amber-200',
  Low:    'bg-gray-100 text-gray-600 border-gray-200',
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusChip({ status }: { status: string }) {
  const m = STATUS_META[status as keyof typeof STATUS_META] || STATUS_META.unknown
  const Icon = m.icon
  return (
    <span className={clsx('inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full border', m.bg, m.color)}>
      <Icon className="w-3 h-3" />
      {m.label}
    </span>
  )
}

function HealthCheckRow({ check, expanded, onToggle }: {
  check: HealthCheck
  expanded: boolean
  onToggle: () => void
}) {
  const m = STATUS_META[check.status] || STATUS_META.unknown
  return (
    <div className={clsx('border rounded-xl mb-2 overflow-hidden', m.bg)}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={onToggle}
      >
        <div className={clsx('w-2 h-2 rounded-full flex-shrink-0', m.dot)} />
        <span className="flex-1 text-sm font-semibold text-gray-800">{check.title}</span>
        {check.requires_live_data && (
          <span className="text-[10px] font-bold text-gray-400 border border-gray-200 rounded px-1.5 py-0.5 bg-white">Live only</span>
        )}
        <StatusChip status={check.status} />
        <ChevronRight className={clsx('w-4 h-4 text-gray-400 flex-shrink-0 transition-transform', expanded && 'rotate-90')} />
      </button>
      {expanded && (
        <div className="px-4 pb-4 border-t border-black/5 pt-3 space-y-2">
          <p className="text-sm text-gray-700">{check.detail}</p>
          {check.recommendation && (
            <div className="flex items-start gap-2 bg-white/70 rounded-lg p-3 border border-black/5">
              <ChevronRight className="w-3.5 h-3.5 text-blue-500 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-gray-600"><strong className="text-blue-700">Recommendation:</strong> {check.recommendation}</p>
            </div>
          )}
          {Object.keys(check.evidence).length > 0 && (
            <div className="bg-gray-900/5 rounded-lg p-2">
              <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wide mb-1">Evidence</p>
              <pre className="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap">
                {JSON.stringify(check.evidence, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CategoryBlock({ category, checks }: { category: string; checks: HealthCheck[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const Icon = CATEGORY_ICONS[category] || Shield
  const fails = checks.filter(c => c.status === 'fail').length
  const warns = checks.filter(c => c.status === 'warn').length

  const toggle = (id: string) => setExpanded(prev => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  return (
    <div className="card mb-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-7 h-7 rounded-md bg-slate-100 flex items-center justify-center">
          <Icon className="w-4 h-4 text-slate-600" />
        </div>
        <h3 className="font-bold text-gray-800 text-sm">{category}</h3>
        <div className="flex gap-1.5 ml-auto">
          {fails > 0 && <span className="text-xs font-bold text-red-700 bg-red-100 px-2 py-0.5 rounded-full">{fails} fail</span>}
          {warns > 0 && <span className="text-xs font-bold text-amber-700 bg-amber-100 px-2 py-0.5 rounded-full">{warns} warn</span>}
        </div>
      </div>
      {checks.map(c => (
        <HealthCheckRow
          key={c.check_id}
          check={c}
          expanded={expanded.has(c.check_id)}
          onToggle={() => toggle(c.check_id)}
        />
      ))}
    </div>
  )
}

// ── Health Score Ring ─────────────────────────────────────────────────────────

function HealthRing({ score, coverage }: { score: number | null; coverage: number }) {
  const r = 40; const circ = 2 * Math.PI * r
  const s = score ?? 0
  const offset = circ - (s / 100) * circ
  const color = score === null ? '#9ca3af' : s >= 80 ? '#10b981' : s >= 60 ? '#f59e0b' : s >= 40 ? '#f97316' : '#ef4444'
  const grade = score === null ? 'N/A' : s >= 80 ? 'Good' : s >= 60 ? 'Fair' : s >= 40 ? 'Poor' : 'Critical'
  const textColor = score === null ? 'text-gray-400' : s >= 80 ? 'text-emerald-600' : s >= 60 ? 'text-amber-600' : s >= 40 ? 'text-orange-600' : 'text-red-600'
  return (
    <div className="flex items-center gap-4">
      <div className="relative w-24 h-24">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
          <circle cx="48" cy="48" r={r} fill="none" stroke="#e5e7eb" strokeWidth="8" />
          {score !== null && (
            <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
              strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
              style={{ transition: 'stroke-dashoffset 1s ease' }} />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score !== null ? (
            <>
              <span className={`text-xl font-extrabold ${textColor}`}>{s}</span>
              <span className="text-[9px] text-gray-400 font-semibold">/100</span>
            </>
          ) : (
            <span className="text-xs font-bold text-gray-400">N/A</span>
          )}
        </div>
      </div>
      <div>
        <p className={`text-2xl font-extrabold ${textColor}`}>{grade}</p>
        <p className="text-xs text-gray-400">Configuration Health</p>
        <p className="text-[10px] text-gray-400 mt-0.5">{coverage}% data coverage</p>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const TABS = ['Overview', 'Config Health', 'NAT Review', 'Attack Surface'] as const
type Tab = typeof TABS[number]

export function HealthAssessment() {
  const routeParams = useParams<{ customerId?: string }>()
  const customerId = routeParams.customerId || ''
  const [searchParams, setSearchParams] = useSearchParams()

  const [policies,       setPolicies]       = useState<Policy[]>([])
  const [selectedPolicy, setSelectedPolicy] = useState(searchParams.get('policy_id') || '')
  const [data,           setData]           = useState<HealthData | null>(null)
  const [loading,        setLoading]        = useState(false)
  const [tab,            setTab]            = useState<Tab>('Overview')
  const [refreshing,     setRefreshing]     = useState(false)

  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    getPolicies(pp).then((list: Policy[]) => {
      const completed = list.filter(p => p.analysis_status === 'completed')
      setPolicies(completed)
      if (!selectedPolicy && completed.length === 1) setSelectedPolicy(completed[0].id)
    })
  }, [customerId])

  useEffect(() => {
    if (!selectedPolicy) { setData(null); return }
    setLoading(true); setData(null)
    api.get(`/policies/${selectedPolicy}/health`)
      .then(r => setData(r.data))
      .finally(() => setLoading(false))
    const next = new URLSearchParams(searchParams)
    next.set('policy_id', selectedPolicy)
    setSearchParams(next, { replace: true })
  }, [selectedPolicy])

  const policy = policies.find(p => p.id === selectedPolicy)

  const refresh = () => {
    if (!selectedPolicy) return
    setRefreshing(true)
    api.get(`/policies/${selectedPolicy}/health`)
      .then(r => setData(r.data))
      .finally(() => setRefreshing(false))
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Firewall Health Assessment</h1>
          <p className="page-subtitle">
            Configuration best-practice checks · NAT review · Attack surface analysis
          </p>
        </div>
        {data && (
          <button onClick={refresh} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={clsx('w-4 h-4', refreshing && 'animate-spin')} />
            Refresh
          </button>
        )}
      </div>

      <div className="page-body max-w-6xl">

        {/* Policy selector */}
        {policies.length > 1 && (
          <div className="card mb-5">
            <h2 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3">Select Policy</h2>
            <div className="flex flex-wrap gap-2">
              {policies.map(p => (
                <button key={p.id} onClick={() => setSelectedPolicy(p.id)}
                  className={clsx(
                    'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium transition-all',
                    selectedPolicy === p.id
                      ? 'border-blue-400 bg-blue-50 text-blue-700 ring-1 ring-blue-300'
                      : 'border-gray-200 bg-gray-50 text-gray-600 hover:bg-white'
                  )}>
                  <Shield className="w-3.5 h-3.5" />
                  {p.firewall_name}
                  {!customerId && p.customer_name ? <span className="text-gray-400">({p.customer_name})</span> : null}
                </button>
              ))}
            </div>
          </div>
        )}

        {!selectedPolicy && !loading && (
          <div className="card empty-state py-16">
            <Shield className="w-12 h-12 text-gray-200 mb-4" />
            <p className="text-lg font-semibold text-gray-500 mb-1">No policy selected</p>
            <p className="text-sm text-gray-400">Select a completed policy to run the health assessment.</p>
          </div>
        )}

        {loading && (
          <div className="flex justify-center py-20">
            <div className="animate-spin w-9 h-9 border-b-2 border-blue-600 rounded-full" />
          </div>
        )}

        {!loading && data && (
          <>
            {/* Summary banner */}
            <div className="card mb-5">
              <div className="flex flex-col md:flex-row items-center md:items-start gap-6">
                <HealthRing score={data.health_score} coverage={data.data_coverage_pct} />

                <div className="flex-1 grid grid-cols-5 gap-3 w-full">
                  {[
                    { label: 'Pass',    val: data.summary.pass,    color: 'text-emerald-600', bg: 'bg-emerald-50' },
                    { label: 'Warn',    val: data.summary.warn,    color: 'text-amber-600',   bg: 'bg-amber-50'   },
                    { label: 'Fail',    val: data.summary.fail,    color: 'text-red-600',     bg: 'bg-red-50'     },
                    { label: 'Info',    val: data.summary.info,    color: 'text-blue-600',    bg: 'bg-blue-50'    },
                    { label: 'N/A',     val: data.summary.unknown, color: 'text-gray-500',    bg: 'bg-gray-50'    },
                  ].map(({ label, val, color, bg }) => (
                    <div key={label} className={clsx('rounded-xl border border-transparent p-3 text-center', bg)}>
                      <p className={`text-2xl font-extrabold ${color}`}>{val}</p>
                      <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wide">{label}</p>
                    </div>
                  ))}
                </div>

                <div className="flex-shrink-0 flex flex-col gap-2">
                  <Link
                    to={policy?.customer_id ? `/customers/${policy.customer_id}/findings?policy_id=${selectedPolicy}` : `/findings?policy_id=${selectedPolicy}`}
                    className="btn-secondary text-xs"
                  >
                    <BarChart2 className="w-3.5 h-3.5" /> Findings
                  </Link>
                  <Link
                    to={policy?.customer_id ? `/customers/${policy.customer_id}/scorecard?policy_id=${selectedPolicy}` : `/scorecard?policy_id=${selectedPolicy}`}
                    className="btn-secondary text-xs"
                  >
                    <TrendingUp className="w-3.5 h-3.5" /> Scorecard
                  </Link>
                </div>
              </div>

              {/* Read-only disclaimer */}
              <div className="flex items-start gap-2 mt-4 bg-orange-50 border border-orange-100 rounded-lg p-3 text-xs text-orange-800">
                <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-orange-500" />
                <span>
                  <strong>Read-only analysis.</strong> This assessment identifies configuration issues for engineer review.
                  No firewall configuration is modified. All changes require formal change approval.
                </span>
              </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 mb-5 bg-gray-100 p-1 rounded-xl w-fit">
              {TABS.map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={clsx(
                    'px-4 py-1.5 rounded-lg text-sm font-semibold transition-all',
                    tab === t ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-500 hover:text-gray-700'
                  )}>
                  {t}
                  {t === 'Config Health' && data.summary.fail > 0 && (
                    <span className="ml-1.5 bg-red-500 text-white text-[10px] rounded-full px-1.5">{data.summary.fail}</span>
                  )}
                  {t === 'NAT Review' && data.nat.total_nat_rules > 0 && (
                    <span className="ml-1.5 bg-blue-500 text-white text-[10px] rounded-full px-1.5">{data.nat.total_nat_rules}</span>
                  )}
                  {t === 'Attack Surface' && data.attack_surface.total_internet_rules > 0 && (
                    <span className="ml-1.5 bg-orange-500 text-white text-[10px] rounded-full px-1.5">{data.attack_surface.total_internet_rules}</span>
                  )}
                </button>
              ))}
            </div>

            {/* ── Overview tab ── */}
            {tab === 'Overview' && (
              <div className="grid md:grid-cols-3 gap-4">
                {/* By category summary */}
                {Object.entries(data.by_category).map(([cat, counts]) => {
                  const Icon = CATEGORY_ICONS[cat] || Shield
                  const fails = counts.fail || 0
                  const warns = counts.warn || 0
                  const passes = counts.pass || 0
                  const status = fails > 0 ? 'fail' : warns > 0 ? 'warn' : 'pass'
                  const m = STATUS_META[status]
                  return (
                    <button key={cat} onClick={() => setTab('Config Health')}
                      className={clsx('card text-left hover:shadow-md transition-all group', m.bg)}>
                      <div className="flex items-center gap-2 mb-3">
                        <div className="w-7 h-7 rounded-md bg-white/60 flex items-center justify-center">
                          <Icon className={clsx('w-4 h-4', m.color)} />
                        </div>
                        <span className="text-sm font-bold text-gray-800">{cat}</span>
                        <ChevronRight className="w-3.5 h-3.5 text-gray-300 ml-auto group-hover:text-gray-500 transition-colors" />
                      </div>
                      <div className="flex gap-2 text-xs">
                        {passes > 0 && <span className="text-emerald-700 font-semibold">{passes} pass</span>}
                        {warns > 0  && <span className="text-amber-700 font-semibold">{warns} warn</span>}
                        {fails > 0  && <span className="text-red-700 font-semibold">{fails} fail</span>}
                        {(counts.unknown || 0) > 0 && <span className="text-gray-400 font-semibold">{counts.unknown} n/a</span>}
                      </div>
                    </button>
                  )
                })}

                {/* Attack surface card */}
                <button onClick={() => setTab('Attack Surface')}
                  className="card text-left hover:shadow-md transition-all group bg-orange-50 border-orange-100">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-7 h-7 rounded-md bg-white/60 flex items-center justify-center">
                      <Globe className="w-4 h-4 text-orange-600" />
                    </div>
                    <span className="text-sm font-bold text-gray-800">Attack Surface</span>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-300 ml-auto group-hover:text-gray-500 transition-colors" />
                  </div>
                  <div className="flex gap-2 text-xs">
                    <span className="text-orange-700 font-semibold">{data.attack_surface.total_internet_rules} internet-facing rules</span>
                    {data.attack_surface.high_risk_rules > 0 && (
                      <span className="text-red-700 font-semibold">{data.attack_surface.high_risk_rules} high-risk</span>
                    )}
                  </div>
                </button>

                {/* NAT card */}
                <button onClick={() => setTab('NAT Review')}
                  className="card text-left hover:shadow-md transition-all group bg-purple-50 border-purple-100">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-7 h-7 rounded-md bg-white/60 flex items-center justify-center">
                      <Network className="w-4 h-4 text-purple-600" />
                    </div>
                    <span className="text-sm font-bold text-gray-800">NAT Review</span>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-300 ml-auto group-hover:text-gray-500 transition-colors" />
                  </div>
                  <div className="flex gap-2 text-xs">
                    <span className="text-purple-700 font-semibold">{data.nat.total_nat_rules} NAT rules</span>
                    {data.nat.unused_nat_rules.length > 0 && (
                      <span className="text-amber-700 font-semibold">{data.nat.unused_nat_rules.length} unused</span>
                    )}
                  </div>
                </button>
              </div>
            )}

            {/* ── Config Health tab ── */}
            {tab === 'Config Health' && (() => {
              const byCategory: Record<string, HealthCheck[]> = {}
              for (const c of data.checks) {
                if (!byCategory[c.category]) byCategory[c.category] = []
                byCategory[c.category].push(c)
              }
              return (
                <div>
                  {data.summary.fail > 0 && (
                    <div className="flex items-center gap-3 bg-red-50 border border-red-200 rounded-xl p-4 mb-5 text-sm text-red-800">
                      <XCircle className="w-5 h-5 flex-shrink-0 text-red-500" />
                      <span>{data.summary.fail} check{data.summary.fail !== 1 ? 's' : ''} failed — review and remediate before next audit.</span>
                    </div>
                  )}
                  {Object.entries(byCategory).map(([cat, checks]) => (
                    <CategoryBlock key={cat} category={cat} checks={checks} />
                  ))}
                </div>
              )
            })()}

            {/* ── NAT Review tab ── */}
            {tab === 'NAT Review' && (
              <div className="space-y-5">
                {/* Summary */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'Total NAT Rules',    value: data.nat.total_nat_rules,           color: 'text-purple-700' },
                    { label: 'Enabled',             value: data.nat.enabled_nat_rules,          color: 'text-blue-700'   },
                    { label: 'Unused (zero-hit)',   value: data.nat.unused_nat_rules.length,    color: 'text-amber-700'  },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="stat-card">
                      <p className={`stat-value ${color}`}>{value}</p>
                      <p className="stat-label">{label}</p>
                    </div>
                  ))}
                </div>

                {/* Unused NAT rules */}
                {data.nat.unused_nat_rules.length > 0 && (
                  <div className="card">
                    <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-500" /> Unused NAT Rules (Zero Hits)
                    </h3>
                    <table className="data-table">
                      <thead><tr>
                        {['Rule', 'Name', 'Sources', 'Destinations', 'Services', 'Hit Count'].map(h => <th key={h}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {data.nat.unused_nat_rules.map(r => (
                          <tr key={r.rule_id}>
                            <td className="font-mono text-gray-500">{r.rule_id}</td>
                            <td className="font-medium">{r.rule_name}</td>
                            <td className="text-xs text-gray-500">{r.sources.join(', ') || '—'}</td>
                            <td className="text-xs text-gray-500">{r.destinations.join(', ') || '—'}</td>
                            <td className="text-xs text-gray-500">{r.services.join(', ') || '—'}</td>
                            <td><span className="badge-medium">0</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Duplicate NAT */}
                {data.nat.duplicate_nat_groups.length > 0 && (
                  <div className="card">
                    <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-500" /> Duplicate NAT Rule Groups
                    </h3>
                    <div className="space-y-2">
                      {data.nat.duplicate_nat_groups.map((grp, i) => (
                        <div key={i} className="flex items-center gap-3 bg-amber-50 border border-amber-100 rounded-lg px-3 py-2">
                          <span className="text-xs font-bold text-amber-700">{grp.count} duplicates</span>
                          <span className="text-xs text-gray-600">{grp.rules.join(', ')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* All NAT rules */}
                {data.nat.nat_entries.length > 0 ? (
                  <div className="card">
                    <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-3">NAT Rule Inventory</h3>
                    <table className="data-table">
                      <thead><tr>
                        {['Rule', 'Name', 'Sources', 'Destinations', 'Services', 'NAT Type', 'Status', 'Hits'].map(h => <th key={h}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {data.nat.nat_entries.map(r => (
                          <tr key={r.rule_id} className={!r.enabled ? 'opacity-50' : ''}>
                            <td className="font-mono text-xs text-gray-500">{r.rule_id}</td>
                            <td className="font-medium text-sm">{r.rule_name}</td>
                            <td className="text-xs text-gray-500 max-w-[120px] truncate" title={r.sources.join(', ')}>{r.sources.join(', ') || '—'}</td>
                            <td className="text-xs text-gray-500 max-w-[120px] truncate" title={r.destinations.join(', ')}>{r.destinations.join(', ') || '—'}</td>
                            <td className="text-xs text-gray-500">{r.services.join(', ') || 'Any'}</td>
                            <td><span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded font-mono">{r.nat_type || 'snat'}</span></td>
                            <td>
                              {r.enabled
                                ? <span className="text-xs text-emerald-600 font-semibold">Enabled</span>
                                : <span className="text-xs text-gray-400">Disabled</span>}
                            </td>
                            <td className="text-xs text-gray-600">{r.hit_count ?? '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="card text-center py-10">
                    <Network className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                    <p className="text-gray-500 text-sm">No NAT rules detected in this policy.</p>
                    <p className="text-gray-400 text-xs mt-1">NAT rules require the nat-enabled flag to be set during parsing.</p>
                  </div>
                )}
              </div>
            )}

            {/* ── Attack Surface tab ── */}
            {tab === 'Attack Surface' && (
              <div className="space-y-5">
                {/* Risk summary */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'Internet-Facing Rules', value: data.attack_surface.total_internet_rules,    color: 'text-orange-600' },
                    { label: 'High-Risk Rules',        value: data.attack_surface.high_risk_rules,         color: 'text-red-600'    },
                    { label: 'Rules Without Logging',  value: data.attack_surface.rules_without_logging,   color: 'text-amber-600'  },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="stat-card">
                      <p className={`stat-value ${color}`}>{value}</p>
                      <p className="stat-label">{label}</p>
                    </div>
                  ))}
                </div>

                {/* Exposed services */}
                {data.attack_surface.exposed_services.length > 0 && (
                  <div className="card">
                    <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <Wifi className="w-4 h-4 text-orange-500" /> Exposed Service Inventory
                    </h3>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      {data.attack_surface.exposed_services.map(svc => (
                        <div key={svc.service} className={clsx(
                          'flex items-center justify-between rounded-xl border p-3',
                          svc.risk === 'High' ? 'bg-red-50 border-red-100' :
                          svc.risk === 'Medium' ? 'bg-amber-50 border-amber-100' : 'bg-gray-50 border-gray-100'
                        )}>
                          <div>
                            <p className="font-bold text-sm text-gray-800">{svc.service}</p>
                            <p className="text-xs text-gray-400">{svc.port ? `Port ${svc.port}` : 'Multiple ports'} · {svc.rule_count} rule{svc.rule_count !== 1 ? 's' : ''}</p>
                          </div>
                          <span className={clsx('text-[10px] font-bold px-2 py-0.5 rounded-full border', RISK_CHIP[svc.risk])}>
                            {svc.risk}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Internet-facing rules table */}
                {data.attack_surface.internet_rules.length > 0 ? (
                  <div className="card">
                    <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-3 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-orange-500" /> Internet-Facing Rules
                    </h3>
                    <table className="data-table">
                      <thead><tr>
                        {['Rule', 'Name', 'Direction', 'Sources', 'Destinations', 'Services', 'Logging', 'Hits'].map(h => <th key={h}>{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {data.attack_surface.internet_rules.map(r => {
                          const highRisk = r.services.some(s => s.risk === 'High')
                          return (
                            <tr key={r.rule_id} className={highRisk ? 'bg-red-50/50' : ''}>
                              <td className="font-mono text-xs text-gray-500">{r.rule_id}</td>
                              <td className="font-medium text-sm">{r.rule_name}</td>
                              <td>
                                <span className={clsx(
                                  'text-[10px] font-bold px-2 py-0.5 rounded-full',
                                  r.direction === 'inbound' ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'
                                )}>
                                  {r.direction}
                                </span>
                              </td>
                              <td className="text-xs text-gray-500 max-w-[100px] truncate" title={r.sources.join(', ')}>{r.sources.join(', ') || '—'}</td>
                              <td className="text-xs text-gray-500 max-w-[100px] truncate" title={r.destinations.join(', ')}>{r.destinations.join(', ') || '—'}</td>
                              <td>
                                <div className="flex flex-wrap gap-1">
                                  {r.services.length > 0 ? r.services.slice(0, 3).map((s, i) => (
                                    <span key={i} className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded border', RISK_CHIP[s.risk])}>
                                      {s.label || s.name}
                                    </span>
                                  )) : <span className="text-xs text-gray-400">Any</span>}
                                </div>
                              </td>
                              <td>
                                {r.logging_enabled
                                  ? <Eye className="w-4 h-4 text-emerald-500" />
                                  : <EyeOff className="w-4 h-4 text-red-400" />}
                              </td>
                              <td className="text-xs text-gray-600">{r.hit_count ?? '—'}</td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="card text-center py-10">
                    <Globe className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                    <p className="text-gray-500 text-sm">No internet-facing rules detected.</p>
                    <p className="text-gray-400 text-xs mt-1">Rules are classified as internet-facing when sources or destinations include 'Any', 'Internet', 'External', or public IP objects.</p>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
