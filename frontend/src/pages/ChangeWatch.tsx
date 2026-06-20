import { useEffect, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import { GitCompareArrows, AlertTriangle, RefreshCw, Plus, Minus, Pencil } from 'lucide-react'
import { getChanges, type PolicyChange } from '../api/client'

const SEV_COLOR: Record<string, string> = {
  Critical: 'text-red-700', High: 'text-red-600',
  Medium: 'text-amber-600', Low: 'text-sky-600', Informational: 'text-slate-500',
}

function fmtDate(iso: string | null) {
  if (!iso) return 'never synced'
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function ChangeWatch() {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''
  const [rows, setRows] = useState<PolicyChange[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    getChanges(customerId || undefined)
      .then(r => setRows(r.policies)).catch(() => setRows([])).finally(() => setLoading(false))
  }, [customerId])
  useEffect(() => { load() }, [load])

  const alerts = rows.filter(r => r.new_high_risk).length

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">What Changed Since Last Sync</h1>
          <p className="page-subtitle">
            Rule additions/removals/modifications and new high-risk exposure per policy, since the previous sync/analysis.
          </p>
        </div>
        <button onClick={load} className="btn-secondary"><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div className="page-body">
        {alerts > 0 && (
          <div className="mb-4 flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-2.5 text-sm text-red-700">
            <AlertTriangle className="w-4 h-4" />
            <span><strong>{alerts}</strong> {alerts === 1 ? 'policy has' : 'policies have'} new high-risk findings since the last analysis.</span>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-16"><div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" /></div>
        ) : rows.length === 0 ? (
          <div className="card text-center py-12">
            <GitCompareArrows className="w-10 h-10 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No changes detected. Re-sync or re-analyze a policy to populate the change feed.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {rows.map(r => (
              <div key={r.policy_id} className={`card ${r.new_high_risk ? 'border-l-4 border-l-red-400' : ''}`}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-bold text-gray-900">{r.firewall_name}</h2>
                      {r.vendor && <span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">{r.vendor}</span>}
                      {r.new_high_risk && <span className="text-[11px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-semibold flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> New high-risk</span>}
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {r.revision_number ? `Revision ${r.revision_number} · ` : ''}Last synced/analyzed: {fmtDate(r.last_synced)}
                    </p>
                  </div>

                  {/* Severity delta */}
                  {Object.keys(r.severity_delta).length > 0 && (
                    <div className="flex flex-wrap gap-2 text-xs font-semibold">
                      {(['Critical', 'High', 'Medium', 'Low', 'Informational'] as const).map(s =>
                        r.severity_delta[s] ? (
                          <span key={s} className={SEV_COLOR[s]}>
                            {r.severity_delta[s] > 0 ? '+' : ''}{r.severity_delta[s]} {s}
                          </span>
                        ) : null,
                      )}
                    </div>
                  )}
                </div>

                {/* Rule change counts */}
                {r.rule_changes_total > 0 && (
                  <div className="flex flex-wrap gap-3 mt-3 text-xs">
                    <span className="flex items-center gap-1 text-emerald-700"><Plus className="w-3.5 h-3.5" /> {r.rules_added} added</span>
                    <span className="flex items-center gap-1 text-red-700"><Minus className="w-3.5 h-3.5" /> {r.rules_removed} removed</span>
                    <span className="flex items-center gap-1 text-amber-700"><Pencil className="w-3.5 h-3.5" /> {r.rules_modified} modified</span>
                  </div>
                )}
                {r.change_summary && <p className="text-xs text-gray-500 mt-2">{r.change_summary}</p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
