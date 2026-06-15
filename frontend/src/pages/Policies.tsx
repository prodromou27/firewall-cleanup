import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import { Loader, RefreshCw, Trash2, Eye, FileText, GitCompare, Shield, BarChart2, TrendingUp } from 'lucide-react'
import { getPolicies, deletePolicy, reanalyzePolicy, getPolicy } from '../api/client'
import { SeverityBadge } from '../components/ui/SeverityBadge'
import type { Policy } from '../types'
import { clsx } from 'clsx'

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

const VENDOR_STYLES: Record<string, string> = {
  FortiGate:  'bg-orange-100 text-orange-800',
  CheckPoint: 'bg-sky-100 text-sky-800',
  PaloAlto:   'bg-purple-100 text-purple-800',
  CiscoASA:   'bg-blue-100 text-blue-800',
}

export function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''

  const load = () => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    getPolicies(pp).then(data => setPolicies(Array.isArray(data) ? data : [])).finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [customerId])

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete policy for ${name}? This cannot be undone.`)) return
    await deletePolicy(id)
    load()
  }

  const handleReanalyze = async (id: string) => {
    await reanalyzePolicy(id)
    load()
  }

  if (loading) {
    return <div className="flex justify-center items-center h-64"><Loader className="animate-spin w-8 h-8 text-blue-600" /></div>
  }

  const uploadLink = customerId ? `/upload?customer_id=${customerId}` : '/upload'

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Policy Inventory</h1>
          <p className="page-subtitle">
            {policies.length} {policies.length === 1 ? 'policy' : 'policies'} · uploaded firewall configurations and analysis status
          </p>
        </div>
        <Link to={uploadLink} className="btn-primary">
          <FileText className="w-4 h-4" /> Upload Policy
        </Link>
      </div>

      <div className="page-body">
        {policies.length === 0 ? (
          <div className="card empty-state">
            <Shield className="w-12 h-12 text-gray-200 mb-4" />
            <p className="text-lg font-semibold text-gray-500 mb-1">No policies yet</p>
            <p className="text-sm text-gray-400 mb-6">Upload a firewall configuration to begin analysis.</p>
            <Link to={uploadLink} className="btn-primary">Upload your first policy</Link>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
            <table className="data-table">
              <thead>
                <tr>
                  {['Customer', 'Firewall', 'Vendor', 'Package', 'Uploaded', 'Rules', 'Findings', 'High Risk', 'Status', ''].map(h => (
                    <th key={h}>{h}</th>
                  ))}
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
                    <td onClick={e => e.stopPropagation()}>
                      <span className={clsx(
                        'text-xs font-semibold px-2 py-0.5 rounded',
                        VENDOR_STYLES[p.vendor] || 'bg-teal-100 text-teal-800'
                      )}>
                        {p.vendor}
                      </span>
                    </td>
                    <td className="text-gray-500">{p.policy_package || '—'}</td>
                    <td className="text-gray-500 whitespace-nowrap">
                      {p.upload_date ? new Date(p.upload_date).toLocaleDateString() : '—'}
                    </td>
                    <td className="text-gray-700 font-medium">{p.rule_count}</td>
                    <td className="text-gray-700">{p.finding_count}</td>
                    <td>
                      {p.high_finding_count > 0 ? (
                        <span className="badge-high">{p.high_finding_count}</span>
                      ) : <span className="text-gray-300 text-xs">—</span>}
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
          </div>
        )}
      </div>
    </div>
  )
}

export function PolicyDetail() {
  const [policy, setPolicy] = useState<Policy & { findings_by_type: Array<{ type: string; count: number }> } | null>(null)
  const [loading, setLoading] = useState(true)
  const { id } = useParams<{ id: string }>()

  useEffect(() => {
    if (id) getPolicy(id).then(setPolicy).finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="flex justify-center items-center h-64"><Loader className="animate-spin w-8 h-8 text-blue-600" /></div>
  if (!policy) return <div className="p-8 text-red-600">Policy not found.</div>

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
          <p className="page-subtitle">{policy.customer_name} · {policy.vendor}{policy.policy_package ? ` · ${policy.policy_package}` : ''}</p>
        </div>
        <div className="flex gap-2">
          <Link to={`/policies/${id}/rules`} className="btn-secondary">View Rulebase</Link>
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
        {(policy.health_score != null || policy.complexity_score != null || policy.cleanup_readiness_score != null) && (
          <div className="card">
            <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide mb-4">Policy Health Scores</h3>
            <div className="grid grid-cols-3 gap-4">
              <ScoreGauge value={policy.health_score} label="Health Score" color="text-emerald-600" />
              <ScoreGauge value={typeof policy.complexity_score === 'number' ? 100 - policy.complexity_score : null} label="Simplicity Score" color="text-blue-600" />
              <ScoreGauge value={policy.cleanup_readiness_score} label="Data Readiness" color="text-amber-600" />
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
