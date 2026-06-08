import { useEffect, useState, useMemo, useCallback } from 'react'
import { useSearchParams, useParams, Link } from 'react-router-dom'
import {
  FileText, Download, ExternalLink, Shield, AlertTriangle,
  FileSpreadsheet, FileJson, Globe, Loader,
  Filter, RotateCcw, Check,
  Eye, EyeOff, Search, Settings2,
} from 'lucide-react'
import { getPolicies, getFindings, getReportUrl, API_KEY } from '../api/client'
import type { Policy } from '../types'
import { clsx } from 'clsx'

/* ── Types ─────────────────────────────────────────────────── */
interface FindingRow {
  id: string
  severity: string
  finding_type: string
  title: string
  status: string
  confidence: string
  recommendation?: string
  description?: string
}

/* ── Constants ─────────────────────────────────────────────── */
const SEVERITIES = ['High', 'Medium', 'Low', 'Informational']
const STATUSES = [
  'New', 'Review Required', 'In Review',
  'Requires Business Validation', 'Requires Customer Confirmation',
  'Confirmed Cleanup Candidate', 'Manual Change Required',
  'Change Planned Outside Tool', 'Cleanup Completed Outside Tool',
  'False Positive', 'Accepted Risk', 'Deferred', 'Reopened',
]

const FINDING_TYPE_LABELS: Record<string, string> = {
  duplicate_rule: 'Duplicate Rules',   shadowed_rule: 'Shadowed Rules',
  disabled_rule: 'Disabled Rules',     zero_hit_rule: 'Zero-Hit Rules',
  overly_permissive: 'Overly Permissive', risky_service: 'Risky Services',
  no_logging: 'No Logging',            temporary_rule: 'Temporary Rules',
  unused_object: 'Unused Objects',     duplicate_object: 'Duplicate Objects',
  low_usage_rule: 'Low Usage Rules',   empty_group: 'Empty Groups',
}

const SEV_COLORS: Record<string, { badge: string; chip: string; dot: string }> = {
  High:          { badge: 'badge-high',   chip: 'bg-red-50 border-red-200 text-red-700',    dot: 'bg-red-500'    },
  Medium:        { badge: 'badge-medium', chip: 'bg-amber-50 border-amber-200 text-amber-700', dot: 'bg-amber-400' },
  Low:           { badge: 'badge-low',    chip: 'bg-blue-50 border-blue-200 text-blue-700',  dot: 'bg-blue-500'   },
  Informational: { badge: 'badge-info',   chip: 'bg-gray-50 border-gray-200 text-gray-500', dot: 'bg-gray-400'   },
}

const FORMAT_CONFIG = [
  {
    format: 'html' as const,
    label: 'HTML Report',
    desc: 'Interactive browser report — shareable, printable',
    icon: Globe,
    action: 'Open in browser',
    badge: 'Recommended',
    color: 'text-blue-600',
    bg: 'bg-blue-50',
  },
  {
    format: 'excel' as const,
    label: 'Excel Workbook',
    desc: 'Multi-sheet workbook with findings and rulebase',
    icon: FileSpreadsheet,
    action: 'Download',
    color: 'text-emerald-600',
    bg: 'bg-emerald-50',
  },
  {
    format: 'csv' as const,
    label: 'CSV Export',
    desc: 'Flat findings list, importable into any tool',
    icon: FileText,
    action: 'Download',
    color: 'text-gray-600',
    bg: 'bg-gray-100',
  },
  {
    format: 'json' as const,
    label: 'JSON Export',
    desc: 'Machine-readable full report with metadata',
    icon: FileJson,
    action: 'Download',
    color: 'text-purple-600',
    bg: 'bg-purple-50',
  },
]

/* ── Helpers ───────────────────────────────────────────────── */
function SevBadge({ sev }: { sev: string }) {
  const c = SEV_COLORS[sev] || SEV_COLORS.Informational
  return <span className={`badge ${c.badge}`}>{sev}</span>
}

function StatusBadge({ status }: { status: string }) {
  const resolved = ['Cleanup Completed Outside Tool','False Positive','Accepted Risk','Deferred']
  const active   = ['In Review','Confirmed Cleanup Candidate','Manual Change Required','Change Planned Outside Tool']
  const cls = resolved.includes(status)
    ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200/80'
    : active.includes(status)
    ? 'bg-blue-50 text-blue-700 ring-1 ring-blue-200/80'
    : 'bg-amber-50 text-amber-700 ring-1 ring-amber-200/80'
  return (
    <span className={`inline-flex text-[10px] font-semibold px-1.5 py-0.5 rounded-md truncate max-w-[120px] ${cls}`} title={status}>
      {status}
    </span>
  )
}

/* ── Main component ────────────────────────────────────────── */
export function Reports() {
  const [searchParams] = useSearchParams()
  const params = useParams<{ customerId?: string }>()
  const customerId = params.customerId || ''

  /* ── Policies ── */
  const [policies, setPolicies] = useState<Policy[]>([])
  const [selectedPolicyId, setSelectedPolicyId] = useState(searchParams.get('policy_id') || '')
  const [loadingPolicies, setLoadingPolicies] = useState(true)

  /* ── Findings ── */
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)

  /* ── Filters ── */
  const [filterSevs, setFilterSevs]   = useState<Set<string>>(new Set(SEVERITIES))
  const [filterStats, setFilterStats] = useState<Set<string>>(new Set(STATUSES)) // all by default
  const [filterTypes, setFilterTypes] = useState<Set<string>>(new Set())
  const [searchText, setSearchText]   = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  /* ── UI state ── */
  const [generating, setGenerating] = useState<string | null>(null)
  const [showFilters, setShowFilters] = useState(true)
  const [includeRules, setIncludeRules] = useState(true)
  const [selectionMode, setSelectionMode] = useState(false) // manual ID picking

  /* ── Load policies ── */
  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    setLoadingPolicies(true)
    getPolicies(pp)
      .then((list: Policy[]) => {
        setPolicies(list)
        if (!selectedPolicyId && list.length === 1) setSelectedPolicyId(list[0].id)
      })
      .finally(() => setLoadingPolicies(false))
  }, [customerId])

  /* ── Load findings when policy changes ── */
  useEffect(() => {
    if (!selectedPolicyId) { setFindings([]); return }
    setLoadingFindings(true)
    getFindings({ policy_id: selectedPolicyId, page_size: 500 })
      .then((r: { findings?: FindingRow[]; } | FindingRow[]) => {
        const list: FindingRow[] = Array.isArray(r) ? r : (r.findings ?? [])
        setFindings(list)
        // Default: all selected
        setSelectedIds(new Set(list.map(f => f.id)))
        // Infer available types
        const types = new Set(list.map(f => f.finding_type))
        setFilterTypes(types)
      })
      .finally(() => setLoadingFindings(false))
  }, [selectedPolicyId])

  /* ── Filtered findings (shown in the list + used for export) ── */
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (!filterSevs.has(f.severity)) return false
      if (!filterStats.has(f.status)) return false
      if (filterTypes.size > 0 && !filterTypes.has(f.finding_type)) return false
      if (searchText) {
        const q = searchText.toLowerCase()
        if (!f.title.toLowerCase().includes(q) &&
            !f.finding_type.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [findings, filterSevs, filterStats, filterTypes, searchText])

  /* ── Keep selectedIds in sync with filteredFindings when not in manual mode ── */
  useEffect(() => {
    if (!selectionMode) {
      setSelectedIds(new Set(filteredFindings.map(f => f.id)))
    }
  }, [filteredFindings, selectionMode])

  // Status quick-group presets
  const RESOLVED_STATUSES = new Set(['Cleanup Completed Outside Tool','False Positive','Accepted Risk','Deferred'])
  const ACTIVE_STATUSES   = new Set(STATUSES.filter(s => !RESOLVED_STATUSES.has(s)))
  const statusGroup = filterStats.size === STATUSES.length ? 'all'
    : [...filterStats].every(s => ACTIVE_STATUSES.has(s)) && filterStats.size === ACTIVE_STATUSES.size ? 'active'
    : [...filterStats].every(s => RESOLVED_STATUSES.has(s)) && filterStats.size === RESOLVED_STATUSES.size ? 'resolved'
    : 'custom'
  const setStatusGroup = (g: 'all' | 'active' | 'resolved') => {
    setSelectionMode(false)
    if (g === 'all')      setFilterStats(new Set(STATUSES))
    else if (g === 'active')   setFilterStats(new Set(ACTIVE_STATUSES))
    else if (g === 'resolved') setFilterStats(new Set(RESOLVED_STATUSES))
  }

  /* ── Toggle helpers ── */
  const toggleSev = (s: string) => {
    setSelectionMode(false)
    setFilterSevs(prev => {
      const n = new Set(prev)
      n.has(s) ? n.delete(s) : n.add(s)
      return n
    })
  }
  const toggleStat = (s: string) => {
    setSelectionMode(false)
    setFilterStats(prev => {
      const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n
    })
  }
  const toggleType = (t: string) => {
    setSelectionMode(false)
    setFilterTypes(prev => {
      const n = new Set(prev); n.has(t) ? n.delete(t) : n.add(t); return n
    })
  }
  const toggleFindingId = (id: string) => {
    setSelectionMode(true)
    setSelectedIds(prev => {
      const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n
    })
  }
  const selectAll = () => {
    setSelectionMode(false)
    setSelectedIds(new Set(filteredFindings.map(f => f.id)))
  }
  const deselectAll = () => {
    setSelectionMode(true)
    setSelectedIds(new Set())
  }
  const resetFilters = useCallback(() => {
    setSelectionMode(false)
    setFilterSevs(new Set(SEVERITIES))
    setFilterStats(new Set(STATUSES))
    setFilterTypes(new Set(findings.map(f => f.finding_type)))
    setSearchText('')
  }, [findings])

  /* ── Counts ── */
  const allTypesInData = useMemo(() => [...new Set(findings.map(f => f.finding_type))], [findings])
  const sevCounts = useMemo(() => {
    const m: Record<string, number> = {}
    filteredFindings.forEach(f => { m[f.severity] = (m[f.severity] || 0) + 1 })
    return m
  }, [filteredFindings])

  /* ── Export ── */
  const buildExportFilters = useCallback(() => {
    const inManualMode = selectionMode
    if (inManualMode && selectedIds.size > 0 && selectedIds.size < filteredFindings.length) {
      return { finding_ids: [...selectedIds], include_rules: includeRules }
    }
    return {
      severities:    [...filterSevs],
      finding_types: [...filterTypes],
      statuses:      [...filterStats],
      include_rules: includeRules,
    }
  }, [selectionMode, selectedIds, filteredFindings, filterSevs, filterTypes, filterStats, includeRules])

  const openReport = async (format: typeof FORMAT_CONFIG[number]['format']) => {
    setGenerating(format)
    const filters = buildExportFilters()
    const url = getReportUrl(selectedPolicyId, format, filters)
    try {
      const headers: HeadersInit = API_KEY ? { 'X-API-Key': API_KEY } : {}
      const resp = await fetch(url, { headers })
      if (!resp.ok) throw new Error(`Report failed: ${resp.status}`)
      const blob = await resp.blob()
      const blobUrl = URL.createObjectURL(blob)
      const ext = format === 'html' ? 'html' : format === 'excel' ? 'xlsx' : format
      const filename = `policylens-report-${selectedPolicyId.slice(0, 8)}.${ext}`
      const a = document.createElement('a')
      a.href = blobUrl
      if (format === 'html') {
        // Open HTML in new tab (works for blob URLs via anchor click)
        a.target = '_blank'
        a.rel = 'noopener'
      } else {
        a.download = filename
      }
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(blobUrl), 10_000)
    } catch (err) {
      console.error('Report export failed', err)
    } finally {
      setTimeout(() => setGenerating(null), 500)
    }
  }

  const policy = policies.find(p => p.id === selectedPolicyId)

  /* ── Render ── */
  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Generate and export audit reports — select exactly what to include</p>
        </div>
        {policy && (
          <Link
            to={policy.customer_id
              ? `/customers/${policy.customer_id}/findings?policy_id=${policy.id}`
              : `/findings?policy_id=${policy.id}`}
            className="btn-secondary"
          >
            <Filter className="w-3.5 h-3.5" /> View Findings
          </Link>
        )}
      </div>

      <div className="page-body max-w-5xl">

        {/* ── Step 1: Policy selector ── */}
        <div className="mb-5">
          <p className="text-[11px] font-bold text-gray-400 uppercase tracking-widest mb-2">
            Step 1 — Select Policy
          </p>
          <div className="card p-0 overflow-hidden">
            {loadingPolicies ? (
              <div className="flex items-center gap-2 text-gray-400 text-sm p-5">
                <Loader className="w-4 h-4 animate-spin" /> Loading policies…
              </div>
            ) : policies.length === 0 ? (
              <div className="text-center py-10 px-5">
                <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                <p className="text-sm text-gray-500 mb-3">No completed policies.</p>
                <Link to={customerId ? `/upload?customer_id=${customerId}` : '/upload'} className="btn-primary text-sm">
                  Upload a Policy
                </Link>
              </div>
            ) : (
              policies.map((p, i) => (
                <button
                  key={p.id}
                  onClick={() => setSelectedPolicyId(p.id)}
                  className={clsx(
                    'w-full flex items-center gap-3 px-5 py-3.5 text-left transition-colors',
                    i > 0 && 'border-t border-gray-100',
                    selectedPolicyId === p.id ? 'bg-gray-50' : 'hover:bg-gray-50/60'
                  )}
                >
                  <div className={clsx(
                    'w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0',
                    selectedPolicyId === p.id ? 'bg-gray-900' : 'bg-gray-100'
                  )}>
                    <Shield className={clsx('w-4 h-4', selectedPolicyId === p.id ? 'text-white' : 'text-gray-400')} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-gray-900 text-sm truncate">{p.firewall_name}</p>
                    <p className="text-xs text-gray-400 truncate">
                      {!customerId && p.customer_name ? `${p.customer_name} · ` : ''}
                      {p.vendor}{p.policy_package ? ` · ${p.policy_package}` : ''}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {p.high_finding_count > 0 && (
                      <span className="badge-high">{p.high_finding_count} High</span>
                    )}
                    <span className="text-xs text-gray-400">{p.finding_count} findings</span>
                    {selectedPolicyId === p.id && <Check className="w-4 h-4 text-gray-900" />}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {selectedPolicyId && policy && (
          <>
            {/* Disclaimer banner */}
            <div className="alert-readonly mb-5">
              <Eye className="w-4 h-4 flex-shrink-0 text-gray-500 mt-0.5" />
              <p className="text-xs leading-relaxed">
                <strong>Read-Only Report.</strong> All findings and recommendations are for analysis purposes only.
                Any remediation requires engineer validation, risk assessment, and formal change approval.
                This platform does not modify firewall rules or configurations.
              </p>
            </div>

            {/* ── Step 2: Filter findings ── */}
            <div className="mb-5">
              <div className="flex items-center justify-between mb-2">
                <p className="text-[11px] font-bold text-gray-400 uppercase tracking-widest">
                  Step 2 — Configure Report Content
                </p>
                <button onClick={() => setShowFilters(v => !v)}
                  className="btn-ghost btn-sm text-xs">
                  <Settings2 className="w-3.5 h-3.5" />
                  {showFilters ? 'Hide' : 'Show'} filters
                </button>
              </div>

              {showFilters && (
                <div className="card p-5 space-y-4">
                  {/* Row 1: Severity filter */}
                  <div>
                    <p className="label-sm mb-2">Severity</p>
                    <div className="flex flex-wrap gap-2">
                      {SEVERITIES.map(sev => {
                        const active = filterSevs.has(sev)
                        const c = SEV_COLORS[sev]
                        return (
                          <button key={sev} onClick={() => toggleSev(sev)}
                            className={clsx(
                              'chip border transition-all',
                              active ? c.chip : 'bg-white border-gray-200 text-gray-400 hover:text-gray-600'
                            )}>
                            <span className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0', active ? c.dot : 'bg-gray-300')} />
                            {sev}
                            <span className="font-normal text-current opacity-60">
                              ({findings.filter(f => f.severity === sev).length})
                            </span>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Row 2: Status filter — grouped presets */}
                  <div>
                    <p className="label-sm mb-2">Status</p>
                    <div className="flex gap-2 flex-wrap">
                      {(['all','active','resolved'] as const).map(g => {
                        const labels = { all: 'All Statuses', active: 'Active / Open', resolved: 'Resolved / Closed' }
                        const counts = {
                          all: findings.length,
                          active: findings.filter(f => ACTIVE_STATUSES.has(f.status)).length,
                          resolved: findings.filter(f => RESOLVED_STATUSES.has(f.status)).length,
                        }
                        const isActive = statusGroup === g
                        return (
                          <button key={g} onClick={() => setStatusGroup(g)}
                            className={clsx('chip border', isActive ? 'chip-active' : 'chip-inactive')}>
                            {labels[g]}
                            <span className="opacity-50 font-normal">({counts[g]})</span>
                          </button>
                        )
                      })}
                      {statusGroup === 'custom' && (
                        <span className="chip border chip-inactive cursor-default opacity-60">Custom selection</span>
                      )}
                    </div>
                  </div>

                  {/* Row 3: Finding type filter */}
                  {allTypesInData.length > 1 && (
                    <div>
                      <p className="label-sm mb-2">Finding Categories</p>
                      <div className="flex flex-wrap gap-2">
                        {allTypesInData.map(t => (
                          <button key={t} onClick={() => toggleType(t)}
                            className={clsx('chip border', filterTypes.has(t) ? 'chip-active' : 'chip-inactive')}>
                            {FINDING_TYPE_LABELS[t] || t.replace(/_/g, ' ')}
                            <span className="opacity-50 font-normal">
                              ({findings.filter(f => f.finding_type === t).length})
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Row 4: Include rules toggle */}
                  <div className="flex items-center gap-3 pt-1 border-t border-gray-100">
                    <button onClick={() => setIncludeRules(v => !v)}
                      className={clsx(
                        'relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0',
                        includeRules ? 'bg-gray-900' : 'bg-gray-200'
                      )}>
                      <span className={clsx(
                        'inline-block h-3.5 w-3.5 rounded-full bg-white shadow transform transition-transform',
                        includeRules ? 'translate-x-4' : 'translate-x-0.5'
                      )} />
                    </button>
                    <span className="text-sm text-gray-600">Include full rulebase in report
                      <span className="text-xs text-gray-400 ml-1">(HTML, Excel, JSON)</span>
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* ── Findings selection list ── */}
            {loadingFindings ? (
              <div className="card flex items-center justify-center py-10">
                <Loader className="w-5 h-5 animate-spin text-gray-400 mr-2" />
                <span className="text-sm text-gray-400">Loading findings…</span>
              </div>
            ) : findings.length > 0 && (
              <div className="mb-5">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[11px] font-bold text-gray-400 uppercase tracking-widest">
                    Findings Selection
                    <span className="ml-2 font-normal normal-case text-gray-400">
                      {selectedIds.size} of {filteredFindings.length} selected
                    </span>
                  </p>
                  <div className="flex items-center gap-2">
                    <button onClick={resetFilters} className="btn-ghost btn-sm text-xs gap-1">
                      <RotateCcw className="w-3 h-3" /> Reset
                    </button>
                    <button onClick={selectAll} className="btn-ghost btn-sm text-xs gap-1">
                      <Check className="w-3 h-3" /> All
                    </button>
                    <button onClick={deselectAll} className="btn-ghost btn-sm text-xs gap-1">
                      <EyeOff className="w-3 h-3" /> None
                    </button>
                  </div>
                </div>

                {/* Search */}
                <div className="relative mb-2">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400" />
                  <input
                    value={searchText}
                    onChange={e => setSearchText(e.target.value)}
                    placeholder="Search findings…"
                    className="input-sm input-search w-full text-sm"
                  />
                </div>

                <div className="card p-0 overflow-hidden">
                  {/* Count bar */}
                  <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-100">
                    <div className="flex items-center gap-3 text-xs text-gray-500">
                      {SEVERITIES.filter(s => sevCounts[s]).map(s => (
                        <span key={s} className={`flex items-center gap-1.5 font-semibold ${
                          s === 'High' ? 'text-red-600' : s === 'Medium' ? 'text-amber-600' :
                          s === 'Low' ? 'text-blue-600' : 'text-gray-500'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${SEV_COLORS[s].dot}`} />
                          {sevCounts[s]} {s}
                        </span>
                      ))}
                    </div>
                    <span className="text-xs text-gray-400">Click to include/exclude individual findings</span>
                  </div>

                  {/* Findings list */}
                  <div className="max-h-80 overflow-y-auto divide-y divide-gray-50">
                    {filteredFindings.length === 0 ? (
                      <div className="text-center py-8 text-gray-400 text-sm">
                        No findings match the filters.
                      </div>
                    ) : filteredFindings.map(f => {
                      const isSelected = selectedIds.has(f.id)
                      return (
                        <button
                          key={f.id}
                          onClick={() => toggleFindingId(f.id)}
                          className={clsx(
                            'w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors',
                            isSelected ? 'hover:bg-gray-50/60' : 'opacity-40 hover:opacity-60',
                          )}
                        >
                          {/* Checkbox */}
                          <div className={clsx(
                            'w-4 h-4 rounded border-2 flex-shrink-0 flex items-center justify-center transition-all',
                            isSelected ? 'border-gray-900 bg-gray-900' : 'border-gray-300 bg-white'
                          )}>
                            {isSelected && <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />}
                          </div>
                          {/* Dot */}
                          <span className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0', SEV_COLORS[f.severity]?.dot || 'bg-gray-400')} />
                          {/* Title */}
                          <span className="flex-1 text-xs text-gray-700 truncate">{f.title}</span>
                          {/* Type */}
                          <span className="text-[10px] text-gray-400 flex-shrink-0 hidden sm:inline">
                            {FINDING_TYPE_LABELS[f.finding_type] || f.finding_type}
                          </span>
                          {/* Status */}
                          <StatusBadge status={f.status} />
                          {/* Severity */}
                          <span className={`flex-shrink-0 badge ${SEV_COLORS[f.severity]?.badge || 'badge-info'}`}>
                            {f.severity}
                          </span>
                        </button>
                      )
                    })}
                  </div>

                  {filteredFindings.length > 0 && (
                    <div className="px-4 py-2 bg-gray-50 border-t border-gray-100 text-xs text-gray-400 text-right">
                      {selectedIds.size} finding{selectedIds.size !== 1 ? 's' : ''} will be included in the report
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ── Step 3: Export formats ── */}
            <div className="mb-5">
              <p className="text-[11px] font-bold text-gray-400 uppercase tracking-widest mb-2">
                Step 3 — Export
              </p>

              {selectedIds.size === 0 && findings.length > 0 && (
                <div className="alert-warning mb-3">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-500 mt-0.5" />
                  <p className="text-xs">No findings selected — the exported report will contain 0 findings.</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                {FORMAT_CONFIG.map(({ format, label, desc, icon: Icon, action, badge, color, bg }) => (
                  <button
                    key={format}
                    onClick={() => openReport(format)}
                    disabled={generating !== null}
                    className={clsx(
                      'card text-left transition-all group relative overflow-hidden disabled:opacity-50',
                      'hover:border-gray-300 hover:shadow-sm active:scale-[0.99]'
                    )}
                  >
                    {badge && (
                      <span className="absolute top-3 right-3 text-[10px] font-bold bg-gray-900 text-white px-2 py-0.5 rounded-full">
                        {badge}
                      </span>
                    )}
                    <div className="flex items-start gap-3.5">
                      <div className={`p-2.5 rounded-lg ${bg} flex-shrink-0`}>
                        {generating === format
                          ? <Loader className={`w-5 h-5 ${color} animate-spin`} />
                          : format === 'html'
                            ? <ExternalLink className={`w-5 h-5 ${color}`} />
                            : <Icon className={`w-5 h-5 ${color}`} />}
                      </div>
                      <div className="min-w-0">
                        <p className="font-semibold text-sm text-gray-900 group-hover:text-gray-700">{label}</p>
                        <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{desc}</p>
                        <div className={`flex items-center gap-1 mt-2 text-xs font-semibold ${color}`}>
                          {format === 'html'
                            ? <><ExternalLink className="w-3 h-3" />{action}</>
                            : <><Download className="w-3 h-3" />{action}</>}

                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              {/* Summary of what will be exported */}
              {findings.length > 0 && (
                <div className="mt-3 p-3.5 bg-gray-50 border border-gray-200 rounded-xl text-xs text-gray-500 space-y-1">
                  <p className="font-semibold text-gray-700 mb-1.5">Export scope:</p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                    <span>Findings included: <strong className="text-gray-900">{selectedIds.size}</strong></span>
                    <span>Rulebase: <strong className="text-gray-900">{includeRules ? 'Included' : 'Excluded'}</strong></span>
                    <span>Severities: <strong className="text-gray-900">{[...filterSevs].join(', ') || 'None'}</strong></span>
                    <span>Statuses: <strong className="text-gray-900">{[...filterStats].join(', ') || 'None'}</strong></span>
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {!selectedPolicyId && !loadingPolicies && policies.length > 0 && (
          <div className="card empty-state py-16">
            <FileText className="w-12 h-12 text-gray-200 mb-4" />
            <p className="text-base font-semibold text-gray-500 mb-1">No policy selected</p>
            <p className="text-sm text-gray-400">Choose a policy above to configure your report.</p>
          </div>
        )}
      </div>
    </div>
  )
}

