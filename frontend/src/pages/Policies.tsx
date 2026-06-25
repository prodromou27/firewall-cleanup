import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import { RefreshCw, Trash2, Eye, FileText, GitCompare, Shield, BarChart2, TrendingUp, Search, ArrowUpDown } from 'lucide-react'
import { getPoliciesPage, deletePolicy, reanalyzePolicy, getPolicy } from '../api/client'
import { SeverityBadge } from '../components/ui/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/page-state'
import { VendorBadge } from '../components/ui/vendor-badge'
import type { Policy } from '../types'
import { clsx } from 'clsx'
import { friendlyErrorMessage } from '../utils/errors'

function StatusChip({ status }: { status: string }) {
  const cls = clsx('inline-flex items-center text-xs font-semibold px-2.5 py-0.5 rounded-full', {
    'bg-blue-100 text-blue-700': status === 'pending' || status === 'parsing',
    'bg-amber-100 text-amber-700': status === 'running',
    'bg-emerald-100 text-emerald-700': status === 'completed',
    'bg-red-100 text-red-700': status === 'failed',
  })
  return (
    <span className={cls}>
      {(status === 'pending' || status === 'parsing' || status === 'running') && (
        <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 animate-pulse" />
      )}
      {status}
    </span>
  )
}

const POLICY_PAGE_SIZE = 50

export function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [vendor, setVendor] = useState('')
  const [status, setStatus] = useState('')
  const [sortBy, setSortBy] = useState('upload_date')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''

  const load = () => {
    setError('')
    const pp: Record<string, string | number> = {
      page,
      page_size: POLICY_PAGE_SIZE,
      sort_by: sortBy,
      sort_dir: sortDir,
    }
    if (customerId) pp.customer_id = customerId
    if (search.trim()) pp.search = search.trim()
    if (vendor) pp.vendor = vendor
    if (status) pp.analysis_status = status
    getPoliciesPage(pp)
      .then(data => { setPolicies(data.policies); setTotal(data.total) })
      .catch(e => {
        setPolicies([])
        setTotal(0)
        setError(friendlyErrorMessage(e, 'Policies could not be loaded. Please refresh and try again.'))
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    setLoading(true)
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [customerId, page, search, vendor, status, sortBy, sortDir])

  const toggleSort = (field: string) => {
    if (sortBy === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else {
      setSortBy(field)
      setSortDir(field === 'firewall_name' || field === 'vendor' || field === 'policy_package' ? 'asc' : 'desc')
    }
    setPage(1)
  }

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete policy for ${name}? This cannot be undone.`)) return
    try {
      await deletePolicy(id)
      load()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Policy could not be deleted. Please try again.'))
    }
  }

  const handleReanalyze = async (id: string) => {
    try {
      await reanalyzePolicy(id)
      load()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Analysis could not be started. Please try again.'))
    }
  }

  if (loading && policies.length === 0) return <LoadingState label="Loading policies..." className="m-7" />

  const uploadLink = customerId ? `/upload?customer_id=${customerId}` : '/upload'
  const pageCount = Math.max(1, Math.ceil(total / POLICY_PAGE_SIZE))

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Policy Inventory</h1>
          <p className="page-subtitle">
            {total.toLocaleString()} {total === 1 ? 'policy' : 'policies'} - uploaded firewall configurations and analysis status
          </p>
        </div>
        <Link to={uploadLink} className="btn-primary">
          <FileText className="w-4 h-4" /> Upload Policy
        </Link>
      </div>

      <div className="page-body">
        <div className="filter-bar mb-5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm w-64 bg-gray-50 focus:bg-white"
              placeholder="Search firewall, package, customer..."
            />
          </div>
          <select value={vendor} onChange={e => { setVendor(e.target.value); setPage(1) }}
            className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white">
            <option value="">All Vendors</option>
            {['FortiGate', 'CheckPoint', 'PaloAlto', 'CiscoASA', 'HuaweiUSG'].map(v => <option key={v} value={v}>{v}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1) }}
            className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white">
            <option value="">All Statuses</option>
            {['pending', 'parsing', 'running', 'completed', 'failed'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        {error ? (
          <ErrorState title="Policies unavailable" message={error} />
        ) : policies.length === 0 ? (
          <EmptyState
            icon={<Shield className="w-7 h-7" />}
            title={search || vendor || status ? 'No policies match the current filters' : 'No policies imported yet'}
            description={search || vendor || status
              ? 'Clear filters or adjust the search to find an imported policy.'
              : 'Upload a firewall configuration to run read-only analysis and start generating findings.'}
            action={<Link to={uploadLink} className="btn-primary">Upload policy</Link>}
          />
        ) : (
          <div className="table-shell table-scroll max-h-[70vh]">
            <table className="data-table">
              <thead className="sticky top-0 z-10">
                <tr>
                  <th>Customer</th>
                  {[
                    ['Firewall', 'firewall_name'],
                    ['Vendor', 'vendor'],
                    ['Package', 'policy_package'],
                    ['Uploaded', 'upload_date'],
                    ['Rules', 'rule_count'],
                    ['Findings', 'finding_count'],
                    ['High Risk', 'high_finding_count'],
                    ['Status', 'analysis_status'],
                  ].map(([label, field]) => (
                    <th key={field}>
                      <button onClick={() => toggleSort(field)} className="inline-flex items-center gap-1 hover:text-blue-600">
                        {label}<ArrowUpDown className="w-3 h-3 opacity-50" />
                      </button>
                    </th>
                  ))}
                  <th />
                </tr>
              </thead>
              <tbody>
                {policies.map(p => (
                  <tr
                    key={p.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/policies/${p.id}/rules`)}
                  >
                    <td className="font-semibold text-gray-900">{p.customer_name}</td>
                    <td className="font-medium text-gray-800">{p.firewall_name}</td>
                    <td onClick={e => e.stopPropagation()}><VendorBadge vendor={p.vendor} /></td>
                    <td className="text-gray-500">{p.policy_package || '-'}</td>
                    <td className="text-gray-500 whitespace-nowrap">
                      {p.upload_date ? new Date(p.upload_date).toLocaleDateString() : '-'}
                    </td>
                    <td className="text-gray-700 font-medium">{p.rule_count}</td>
                    <td className="text-gray-700">{p.finding_count}</td>
                    <td>
                      {p.high_finding_count > 0 ? (
                        <span className="badge-high">{p.high_finding_count}</span>
                      ) : <span className="text-gray-300 text-xs">-</span>}
                    </td>
                    <td><StatusChip status={p.analysis_status} /></td>
                    <td onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-0.5">
                        <button onClick={() => navigate(`/policies/${p.id}`)}
                          title="View details"
                          className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-blue-600 transition-colors">
                          <Eye className="w-4 h-4" />
                        </button>
                        <button onClick={() => navigate(`/policies/${p.id}/rules`)}
                          title="View rulebase"
                          className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-blue-600 transition-colors">
                          <FileText className="w-4 h-4" />
                        </button>
                        <button onClick={() => navigate(`/policies/${p.id}/compare`)}
                          title="Compare revisions"
                          className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-purple-600 transition-colors">
                          <GitCompare className="w-4 h-4" />
                        </button>
                        <button onClick={() => handleReanalyze(p.id)}
                          title="Re-analyze"
                          className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-amber-600 transition-colors">
                          <RefreshCw className="w-4 h-4" />
                        </button>
                        <button onClick={() => handleDelete(p.id, p.firewall_name)}
                          title="Delete"
                          className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-red-600 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 text-sm bg-gray-50">
              <span className="text-gray-500">Page {page} of {pageCount} - {total.toLocaleString()} policies</span>
              <div className="flex gap-2">
                <button onClick={() => setPage(1)} disabled={page === 1} className="btn-secondary py-1 px-2 text-xs disabled:opacity-40">First</button>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Prev</button>
                <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} disabled={page === pageCount} className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Next</button>
                <button onClick={() => setPage(pageCount)} disabled={page === pageCount} className="btn-secondary py-1 px-2 text-xs disabled:opacity-40">Last</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export function PolicyDetail() {
  const [policy, setPolicy] = useState<Policy & { findings_by_type: Array<{ type: string; count: number }> } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const { id } = useParams<{ id: string }>()

  useEffect(() => {
    if (id) {
      setLoading(true)
      setError('')
      getPolicy(id)
        .then(setPolicy)
        .catch(e => {
          setPolicy(null)
          setError(friendlyErrorMessage(e, 'Policy details could not be loaded. Please return to the policy inventory and try again.'))
        })
        .finally(() => setLoading(false))
    }
  }, [id])

  if (loading) return <LoadingState label="Loading policy..." className="m-7" />
  if (error) return <div className="p-7"><ErrorState title="Policy unavailable" message={error} /></div>
  if (!policy) return <div className="p-7"><ErrorState title="Policy unavailable" message="This policy could not be found or is no longer accessible." /></div>

  const TYPE_LABELS: Record<string, string> = {
    duplicate_rule: 'Duplicate Rules',
    shadowed_rule: 'Shadowed Rules',
    disabled_rule: 'Disabled Rules',
    zero_hit_rule: 'Zero-Hit Rules',
    low_usage_rule: 'Low Usage Rules',
    overly_permissive: 'Overly Permissive',
    risky_service: 'Risky Services',
    no_logging: 'No Logging',
    temporary_rule: 'Temporary Rules',
    unused_object: 'Unused Objects',
    duplicate_object: 'Duplicate Objects',
    no_documentation: 'No Documentation',
    naming_quality: 'Poor Rule Names',
    expired_rule: 'Expired Schedules',
    nat_complexity: 'NAT Rules',
    vpn_access: 'Broad VPN Access',
    negated_object: 'Negated Objects',
    rdp_exposed: 'RDP Exposed',
    ssh_exposed: 'SSH Exposed',
    database_exposed: 'Database Exposed',
    cleartext_service: 'Cleartext Protocol',
    inbound_from_internet: 'Inbound From Internet',
    lateral_movement_risk: 'Lateral Movement Risk',
    mergeable_rules: 'Consolidation Candidate',
    no_cleanup_rule: 'Missing Cleanup Rule',
    rule_order_optimization: 'Rule Order Optimization',
    large_rule_section: 'Oversized Section',
    empty_group: 'Empty Groups',
    large_group: 'Large Groups',
    broad_network: 'Broad Networks',
    service_range: 'Large Port Ranges',
  }

  const statCards = [
    { value: policy.rule_count,         label: 'Total Rules',    color: 'text-blue-600' },
    { value: policy.object_count,        label: 'Objects',        color: 'text-gray-700' },
    { value: policy.finding_count,       label: 'Total Findings', color: 'text-amber-600' },
    { value: policy.high_finding_count,  label: 'High Risk',      color: 'text-red-600' },
  ]

  function ScoreGauge({ value, label, color }: { value: number | null | undefined; label: string; color: string }) {
    const v = value ?? 0
    return (
      <div className="bg-gray-50 border border-gray-100 rounded-xl p-4">
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wide mb-2">{label}</p>
        <div className="flex items-end gap-2 mb-2">
          <span className={`text-2xl font-extrabold ${color}`}>{v}</span>
          <span className="text-xs text-gray-400 mb-0.5">/100</span>
        </div>
        <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${color.replace('text-', 'bg-')}`} style={{ width: `${v}%` }} />
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">{policy.firewall_name}</h1>
          <p className="page-subtitle">{policy.customer_name} Â· {policy.vendor}{policy.policy_package ? ` Â· ${policy.policy_package}` : ''}</p>
        </div>
        <div className="flex gap-2">
          <Link to={`/policies/${id}/rules`} className="btn-secondary">View Rulebase</Link>
          <Link to={`/policies/${id}/public-exposure`} className="btn-secondary">Public Exposure</Link>
          <Link to={policy.customer_id ? `/customers/${policy.customer_id}/findings?policy_id=${id}` : `/findings?policy_id=${id}`} className="btn-secondary">
            <BarChart2 className="w-4 h-4" /> Findings
          </Link>
          <Link to={policy.customer_id ? `/customers/${policy.customer_id}/scorecard?policy_id=${id}` : `/scorecard?policy_id=${id}`} className="btn-secondary">
            <TrendingUp className="w-4 h-4" /> Scorecard
          </Link>
          <Link to={policy.customer_id ? `/customers/${policy.customer_id}/reports?policy_id=${id}` : `/reports?policy_id=${id}`} className="btn-primary">
            <FileText className="w-4 h-4" /> Generate Report
          </Link>
        </div>
      </div>

      <div className="page-body space-y-6">
        {/* Stat row */}
        <div className="grid grid-cols-4 gap-4">
          {statCards.map(({ value, label, color }) => (
            <div key={label} className="stat-card">
              <p className={`stat-value ${color}`}>{value}</p>
              <p className="stat-label">{label}</p>
            </div>
          ))}
        </div>

        {/* Score gauges */}
        {(policy.health_score != null || policy.complexity_score != null || policy.cleanup_readiness_score != null || policy.import_quality_score != null) && (
          <div className="card">
            <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-4">Policy Health Scores</h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <ScoreGauge value={policy.health_score} label="Health Score" color="text-emerald-600" />
              <ScoreGauge value={typeof policy.complexity_score === 'number' ? 100 - policy.complexity_score : null} label="Simplicity Score" color="text-blue-600" />
              <ScoreGauge value={policy.cleanup_readiness_score} label="Data Readiness" color="text-amber-600" />
              <ScoreGauge value={policy.import_quality_score} label="Import Quality" color="text-violet-600" />
            </div>
            {policy.top_risk_drivers && policy.top_risk_drivers.length > 0 && (
              <div className="mt-4 pt-4 border-t border-gray-100">
                <p className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-2">Top Risk Drivers</p>
                <div className="flex flex-wrap gap-2">
                  {policy.top_risk_drivers.map(d => (
                    <span key={d.type} className="flex items-center gap-1 bg-red-50 text-red-700 border border-red-100 rounded-lg px-2.5 py-1 text-xs font-semibold">
                      {TYPE_LABELS[d.type] || d.type.replace(/_/g, ' ')}
                      <span className="bg-red-600 text-white rounded-full px-1.5 py-px text-[10px]">{d.count}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Severity breakdown */}
        {policy.findings_by_severity && (
          <div className="card">
            <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-4">Findings by Severity</h3>
            <div className="flex gap-4">
              {policy.findings_by_severity.map(s => (
                <div key={s.severity} className="flex items-center gap-2">
                  <SeverityBadge severity={s.severity} />
                  <span className="font-bold text-gray-800">{s.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* By type */}
        {policy.findings_by_type && policy.findings_by_type.length > 0 && (
          <div className="card">
            <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-4">Findings by Type</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {policy.findings_by_type.map(t => (
                <div key={t.type} className="flex justify-between items-center bg-gray-50 hover:bg-blue-50 border border-gray-100 rounded-lg px-3 py-2.5 transition-colors">
                  <span className="text-sm text-gray-600">{TYPE_LABELS[t.type] || t.type.replace(/_/g, ' ')}</span>
                  <span className="text-sm font-bold text-blue-700 ml-3">{t.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
