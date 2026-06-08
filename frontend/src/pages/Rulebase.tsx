import { useEffect, useState, useCallback, useRef } from 'react'
import { useParams, Link, useSearchParams } from 'react-router-dom'
import {
  Search, ChevronDown, ChevronUp, AlertTriangle, ChevronRight,
  Download, SlidersHorizontal, X, Shield, Zap, Eye, EyeOff,
  ArrowUpDown, ArrowUp, ArrowDown, Filter,
} from 'lucide-react'
import { getRules, getPolicy, getRulesExportUrl, API_KEY } from '../api/client'
import { SeverityBadge } from '../components/ui/SeverityBadge'
import type { Rule, Policy } from '../types'
import { clsx } from 'clsx'

// ── Helpers ───────────────────────────────────────────────────────────────────

function RiskBadge({ score }: { score: number }) {
  const [bg, text] =
    score >= 75 ? ['bg-red-100', 'text-red-700'] :
    score >= 50 ? ['bg-amber-100', 'text-amber-700'] :
    score >= 25 ? ['bg-blue-100', 'text-blue-700'] :
                  ['bg-gray-100', 'text-gray-500']
  return (
    <span className={clsx('text-xs font-bold px-1.5 py-0.5 rounded tabular-nums', bg, text)}>
      {score}
    </span>
  )
}

function AnyBadge() {
  return <span className="px-1 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 border border-red-200">ANY</span>
}

function parseValues(v: unknown): string[] {
  if (Array.isArray(v)) return v as string[]
  if (typeof v === 'string' && v.trim().startsWith('[')) {
    try { return JSON.parse(v) } catch { /* fall through */ }
  }
  if (typeof v === 'string' && v.length > 0) return [v]
  return []
}

function ValueCell({ values, isAny }: { values: unknown; isAny?: boolean }) {
  const arr = parseValues(values)
  if (!arr || arr.length === 0) return <span className="text-gray-300 text-xs">—</span>
  if (isAny) return <AnyBadge />
  const shown = arr.slice(0, 3)
  return (
    <div className="flex flex-wrap gap-0.5 max-w-[140px]">
      {shown.map((v, i) => (
        <span key={i} className="px-1 py-0.5 bg-gray-50 border border-gray-200 rounded text-[10px] font-mono text-gray-700 truncate max-w-[100px]" title={v}>{v}</span>
      ))}
      {arr.length > 3 && <span className="text-[10px] text-gray-400">+{arr.length - 3}</span>}
    </div>
  )
}

function FindingTypeBadge({ type }: { type: string }) {
  const labels: Record<string, string> = {
    shadowed_rule: 'Shadow', duplicate_rule: 'Dup', zero_hit_rule: 'Zero Hit',
    overly_permissive: 'Permissive', disabled_rule: 'Disabled',
    no_logging: 'No Log', risky_service: 'Risky Svc', temporary_rule: 'Temp',
  }
  return (
    <span className="text-[10px] px-1 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-700 font-medium">
      {labels[type] || type}
    </span>
  )
}

type SortField = 'rule_number' | 'risk_score' | 'hit_count' | 'rule_name'
type SortDir = 'asc' | 'desc'

function SortHeader({
  label, field, current, dir, onClick,
}: {
  label: string; field: SortField; current: SortField; dir: SortDir
  onClick: (f: SortField) => void
}) {
  const active = current === field
  return (
    <th
      className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap cursor-pointer hover:text-blue-600 select-none"
      onClick={() => onClick(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active ? (dir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />) : <ArrowUpDown className="w-3 h-3 opacity-30" />}
      </span>
    </th>
  )
}

// ── Rule Row ──────────────────────────────────────────────────────────────────

function RuleRow({ rule }: { rule: Rule }) {
  const [expanded, setExpanded] = useState(false)
  const hasFindings = (rule.finding_count ?? 0) > 0
  const isPermissive = (rule as any).is_permissive
  const isDisabled = !rule.enabled

  return (
    <>
      <tr
        className={clsx(
          'cursor-pointer text-sm transition-colors',
          isDisabled  && 'opacity-50 bg-gray-50',
          hasFindings && !isDisabled && 'bg-amber-50/40 hover:bg-amber-50',
          !hasFindings && !isDisabled && 'hover:bg-blue-50/30',
          expanded    && 'bg-blue-50',
        )}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-3 py-2 text-gray-400 font-mono text-xs w-10">{rule.rule_number}</td>
        <td className="px-3 py-2">
          <div className="font-medium text-gray-900 truncate max-w-[200px]" title={rule.rule_name || undefined}>
            {rule.rule_name || <span className="text-gray-400 italic">Unnamed</span>}
          </div>
          {rule.section && <div className="text-[10px] text-gray-400 truncate">{rule.section}</div>}
        </td>
        <td className="px-3 py-2">
          <ValueCell values={rule.sources || []} isAny={(rule as any).src_any} />
        </td>
        <td className="px-3 py-2">
          <ValueCell values={rule.destinations || []} isAny={(rule as any).dst_any} />
        </td>
        <td className="px-3 py-2">
          <ValueCell values={rule.services || []} isAny={(rule as any).svc_any} />
        </td>
        <td className="px-3 py-2">
          <span className={clsx(
            'text-xs font-semibold px-1.5 py-0.5 rounded',
            rule.action === 'accept' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-600',
          )}>
            {rule.action || '—'}
          </span>
        </td>
        <td className="px-3 py-2">
          {rule.enabled
            ? <span className="text-xs text-green-600 font-semibold">●</span>
            : <span className="text-xs text-gray-400 font-semibold">○</span>}
        </td>
        <td className="px-3 py-2 text-xs text-gray-500 tabular-nums">
          {rule.hit_count !== null && rule.hit_count !== undefined
            ? <span className={rule.hit_count === 0 ? 'text-amber-600 font-semibold' : ''}>{rule.hit_count.toLocaleString()}</span>
            : <span className="text-gray-300">—</span>}
        </td>
        <td className="px-3 py-2"><RiskBadge score={rule.risk_score || 0} /></td>
        <td className="px-3 py-2">
          <div className="flex flex-wrap gap-0.5">
            {hasFindings && (
              <span className="inline-flex items-center gap-0.5 text-xs text-amber-700 font-semibold">
                <AlertTriangle className="w-3 h-3" />{rule.finding_count}
              </span>
            )}
            {(rule as any).finding_types?.slice(0, 2).map((t: string) => (
              <FindingTypeBadge key={t} type={t} />
            ))}
          </div>
        </td>
        <td className="px-3 py-2 text-gray-300 w-6">
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </td>
      </tr>

      {expanded && (
        <tr className="border-b border-blue-100">
          <td colSpan={11} className="px-4 pb-4 bg-blue-50">
            <div className="grid grid-cols-3 gap-6 text-xs pt-3">
              {/* Column 1 */}
              <div className="space-y-2">
                <p className="font-semibold text-gray-600 uppercase tracking-wide text-[10px]">Traffic</p>
                <div className="space-y-1">
                  <div className="flex gap-2">
                    <span className="text-gray-400 w-20 shrink-0">Source</span>
                    <ValueCell values={rule.sources || []} isAny={(rule as any).src_any} />
                  </div>
                  <div className="flex gap-2">
                    <span className="text-gray-400 w-20 shrink-0">Destination</span>
                    <ValueCell values={rule.destinations || []} isAny={(rule as any).dst_any} />
                  </div>
                  <div className="flex gap-2">
                    <span className="text-gray-400 w-20 shrink-0">Service</span>
                    <ValueCell values={rule.services || []} isAny={(rule as any).svc_any} />
                  </div>
                  {(rule.applications?.length ?? 0) > 0 && (
                    <div className="flex gap-2">
                      <span className="text-gray-400 w-20 shrink-0">Application</span>
                      <ValueCell values={rule.applications || []} />
                    </div>
                  )}
                </div>
              </div>
              {/* Column 2 */}
              <div className="space-y-2">
                <p className="font-semibold text-gray-600 uppercase tracking-wide text-[10px]">Rule Details</p>
                <div className="space-y-1">
                  <p><span className="text-gray-400 w-20 inline-block">Rule ID</span><span className="font-mono">{rule.rule_id || '—'}</span></p>
                  <p><span className="text-gray-400 w-20 inline-block">Action</span>
                    <span className={clsx('font-semibold', rule.action === 'accept' ? 'text-green-700' : 'text-red-600')}>{rule.action}</span>
                  </p>
                  <p><span className="text-gray-400 w-20 inline-block">Status</span>
                    <span className={rule.enabled ? 'text-green-700' : 'text-red-600'}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
                  </p>
                  <p><span className="text-gray-400 w-20 inline-block">Logging</span>
                    <span className={rule.logging_enabled ? 'text-green-700' : 'text-red-600 font-semibold'}>{rule.logging_enabled ? 'Enabled' : '⚠ Disabled'}</span>
                  </p>
                  {rule.schedule && <p><span className="text-gray-400 w-20 inline-block">Schedule</span>{rule.schedule}</p>}
                  {rule.nat_enabled && <p><span className="text-gray-400 w-20 inline-block">NAT</span><span className="text-blue-600">Yes</span></p>}
                </div>
              </div>
              {/* Column 3 */}
              <div className="space-y-2">
                <p className="font-semibold text-gray-600 uppercase tracking-wide text-[10px]">Usage</p>
                <div className="space-y-1">
                  <p><span className="text-gray-400 w-20 inline-block">Hit Count</span>
                    <span className={rule.hit_count === 0 ? 'text-amber-600 font-semibold' : ''}>
                      {rule.hit_count !== null && rule.hit_count !== undefined ? rule.hit_count.toLocaleString() : '—'}
                    </span>
                  </p>
                  {rule.last_hit && <p><span className="text-gray-400 w-20 inline-block">Last Hit</span>{rule.last_hit}</p>}
                  {rule.first_hit && <p><span className="text-gray-400 w-20 inline-block">First Hit</span>{rule.first_hit}</p>}
                  <p><span className="text-gray-400 w-20 inline-block">Risk Score</span><RiskBadge score={rule.risk_score || 0} /></p>
                  {rule.comments && (
                    <p className="mt-2 italic text-gray-500 bg-white border border-gray-200 rounded px-2 py-1">{rule.comments}</p>
                  )}
                </div>
              </div>
            </div>

            {/* Findings for this rule */}
            {hasFindings && (
              <div className="mt-3 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                <p className="text-xs font-semibold text-amber-700 mb-1 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> {rule.finding_count} Finding{rule.finding_count !== 1 ? 's' : ''} on this rule
                </p>
                <div className="flex flex-wrap gap-1">
                  {(rule as any).finding_types?.map((t: string) => (
                    <FindingTypeBadge key={t} type={t} />
                  ))}
                </div>
              </div>
            )}

            {/* Permissive warning */}
            {isPermissive && (
              <div className="mt-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-xs text-red-700">
                <span className="font-semibold">⚠ Overly Permissive: </span>
                {[
                  (rule as any).src_any && 'Source = Any',
                  (rule as any).dst_any && 'Destination = Any',
                  (rule as any).svc_any && 'Service = Any',
                ].filter(Boolean).join(' · ')}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export function Rulebase() {
  const { policyId } = useParams<{ policyId: string }>()
  const [searchParams] = useSearchParams()

  const [rules, setRules] = useState<Rule[]>([])
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)

  // Filters
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')
  const [zeroHitsOnly, setZeroHitsOnly] = useState(false)
  const [hasFindings, setHasFindings] = useState<boolean | null>(null)
  const [hasAny, setHasAny] = useState<boolean | null>(null)
  const [minRisk, setMinRisk] = useState<number | null>(null)

  const [exporting, setExporting] = useState(false)

  // Sorting
  const [sortBy, setSortBy] = useState<SortField>('rule_number')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [searchInput, setSearchInput] = useState('')

  const handleSearchInput = (val: string) => {
    setSearchInput(val)
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => { setSearch(val); setPage(1) }, 300)
  }

  const handleSort = (field: SortField) => {
    if (sortBy === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(field)
      setSortDir('asc')
    }
    setPage(1)
  }

  const activeFilters = [
    actionFilter && `Action: ${actionFilter}`,
    enabledFilter && `Status: ${enabledFilter === 'true' ? 'Enabled' : 'Disabled'}`,
    zeroHitsOnly && 'Zero Hits',
    hasFindings === true && 'Has Findings',
    hasAny === true && 'Has ANY',
    minRisk !== null && `Risk ≥ ${minRisk}`,
  ].filter(Boolean)

  const clearFilters = () => {
    setActionFilter(''); setEnabledFilter(''); setZeroHitsOnly(false)
    setHasFindings(null); setHasAny(null); setMinRisk(null)
    setSearchInput(''); setSearch(''); setPage(1)
  }

  const buildParams = () => {
    const p: Record<string, string | number | boolean> = { page, page_size: 100, sort_by: sortBy, sort_dir: sortDir }
    if (search) p.search = search
    if (actionFilter) p.action = actionFilter
    if (enabledFilter !== '') p.enabled = enabledFilter === 'true'
    if (zeroHitsOnly) p.zero_hits = true
    if (hasFindings !== null) p.has_findings = hasFindings
    if (hasAny !== null) p.has_any = hasAny
    if (minRisk !== null) p.min_risk = minRisk
    return p
  }

  const load = useCallback(() => {
    if (!policyId) return
    setLoading(true)
    getRules(policyId, buildParams())
      .then(r => { setRules(r.rules); setTotal(r.total) })
      .finally(() => setLoading(false))
  }, [policyId, page, search, actionFilter, enabledFilter, zeroHitsOnly, hasFindings, hasAny, minRisk, sortBy, sortDir])

  useEffect(() => { load() }, [load])
  useEffect(() => { if (policyId) getPolicy(policyId).then(setPolicy) }, [policyId])

  const pageCount = Math.ceil(total / 100)

  const handleExportCsv = async () => {
    if (!policyId) return
    setExporting(true)
    try {
      const url = getRulesExportUrl(policyId, { ...buildParams(), page: 1, page_size: 9999 })
      const res = await fetch(url, { headers: API_KEY ? { 'X-API-Key': API_KEY } : {} })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = 'rulebase.csv'
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e) {
      console.error('CSV export failed', e)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div>
      {/* ── Header ── */}
      <div className="page-header sticky top-0 z-10">
        <div>
          {policy?.customer_id && (
            <div className="flex items-center gap-1 text-xs text-gray-400 mb-1">
              <Link to="/customers" className="hover:text-blue-600">Customers</Link>
              <ChevronRight className="w-3 h-3" />
              <Link to={`/customers/${policy.customer_id}`} className="hover:text-blue-600">{policy.customer_name}</Link>
              <ChevronRight className="w-3 h-3" />
              <span className="text-gray-600 font-medium">{policy.firewall_name}</span>
            </div>
          )}
          <h1 className="page-title">Rulebase</h1>
          <p className="page-subtitle">
            {policy
              ? `${policy.firewall_name} · ${policy.vendor}${policy.policy_package ? ` · ${policy.policy_package}` : ''}`
              : 'Loading…'}
            {' '}· {total.toLocaleString()} rules
          </p>
        </div>
        <div className="flex gap-2">
          {policy?.customer_id && (
            <Link to={`/customers/${policy.customer_id}/findings?policy_id=${policyId}`} className="btn-secondary">
              <AlertTriangle className="w-4 h-4 text-amber-500" /> Findings
            </Link>
          )}
          <button onClick={handleExportCsv} disabled={exporting} className="btn-secondary">
            <Download className="w-4 h-4" /> {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>
    <div className="page-body">
      {/* ── Filter Bar ── */}
      <div className="bg-white border border-gray-100 rounded-xl p-3 mb-4 shadow-sm">
        <div className="flex flex-wrap gap-2 items-center">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" />
            <input
              value={searchInput}
              onChange={e => handleSearchInput(e.target.value)}
              className="pl-8 pr-3 py-1.5 border border-gray-300 rounded text-sm w-56 focus:outline-none focus:ring-2 focus:ring-blue-300"
              placeholder="Search rules, comments…"
            />
          </div>

          <select value={actionFilter} onChange={e => { setActionFilter(e.target.value); setPage(1) }}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm text-gray-700">
            <option value="">All Actions</option>
            <option value="accept">Accept</option>
            <option value="deny">Deny</option>
          </select>

          <select value={enabledFilter} onChange={e => { setEnabledFilter(e.target.value); setPage(1) }}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm text-gray-700">
            <option value="">All Status</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>

          {/* Quick filter chips */}
          {[
            { label: '⚡ Zero Hits', active: zeroHitsOnly, onClick: () => { setZeroHitsOnly(z => !z); setPage(1) } },
            { label: '⚠ Has Findings', active: hasFindings === true, onClick: () => { setHasFindings(f => f === true ? null : true); setPage(1) } },
            { label: '🔓 Has ANY', active: hasAny === true, onClick: () => { setHasAny(a => a === true ? null : true); setPage(1) } },
            { label: '🔴 High Risk (≥75)', active: minRisk === 75, onClick: () => { setMinRisk(m => m === 75 ? null : 75); setPage(1) } },
          ].map(({ label, active, onClick }) => (
            <button key={label} onClick={onClick}
              className={clsx(
                'px-2.5 py-1.5 rounded text-xs font-semibold border transition-all',
                active ? 'bg-blue-600 text-white border-blue-600' : 'border-gray-200 text-gray-600 hover:bg-gray-50',
              )}>
              {label}
            </button>
          ))}

          {activeFilters.length > 0 && (
            <button onClick={clearFilters}
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-500 hover:text-red-600 border border-gray-200 rounded hover:border-red-300 transition-colors">
              <X className="w-3 h-3" /> Clear ({activeFilters.length})
            </button>
          )}

          <div className="flex-1" />
          <span className="text-xs text-gray-400">
            {total.toLocaleString()} rule{total !== 1 ? 's' : ''}
            {activeFilters.length > 0 && ' (filtered)'}
          </span>
        </div>
      </div>

      {/* ── Table ── */}
      {loading ? (
        <div className="flex justify-center py-16">
          <div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" />
        </div>
      ) : rules.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="font-medium">No rules match the current filters</p>
          <button onClick={clearFilters} className="mt-3 text-sm text-blue-600 hover:underline">Clear filters</button>
        </div>
      ) : (
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-x-auto">
          {/* Legend */}
          <div className="flex items-center gap-4 px-3 py-2 bg-gray-50 border-b border-gray-100 text-[11px] text-gray-500">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-amber-100 border border-amber-300 inline-block" /> Has findings</span>
            <span className="flex items-center gap-1"><span className="font-bold text-red-600">ANY</span> = wildcard (overly permissive)</span>
            <span className="flex items-center gap-1"><span className="text-amber-600 font-semibold">0</span> = zero-hit rule</span>
          </div>

          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <SortHeader label="#" field="rule_number" current={sortBy} dir={sortDir} onClick={handleSort} />
                <SortHeader label="Rule Name" field="rule_name" current={sortBy} dir={sortDir} onClick={handleSort} />
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Source</th>
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Destination</th>
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Service</th>
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Action</th>
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">On</th>
                <SortHeader label="Hits" field="hit_count" current={sortBy} dir={sortDir} onClick={handleSort} />
                <SortHeader label="Risk" field="risk_score" current={sortBy} dir={sortDir} onClick={handleSort} />
                <th className="px-3 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Findings</th>
                <th className="w-6" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rules.map(r => <RuleRow key={r.id} rule={r} />)}
            </tbody>
          </table>

          {pageCount > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 text-sm bg-gray-50">
              <span className="text-gray-500 text-xs">
                Page {page} of {pageCount} · {total} rules total
              </span>
              <div className="flex gap-2">
                <button onClick={() => setPage(1)} disabled={page === 1}
                  className="btn-secondary py-1 px-2 text-xs disabled:opacity-40">«</button>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Prev</button>
                <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} disabled={page === pageCount}
                  className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Next</button>
                <button onClick={() => setPage(pageCount)} disabled={page === pageCount}
                  className="btn-secondary py-1 px-2 text-xs disabled:opacity-40">»</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>{/* end page-body */}
    </div>
  )
}
