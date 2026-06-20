import { useEffect, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import { ListChecks, Download, ShieldCheck, Wrench, Trash2, TrendingDown } from 'lucide-react'
import { getCleanupPlan, getCleanupTicketsUrl, type CleanupPlan as Plan } from '../api/client'

const WAVE_ICON: Record<number, React.ReactNode> = {
  1: <Trash2 className="w-5 h-5" />,
  2: <Wrench className="w-5 h-5" />,
  3: <ShieldCheck className="w-5 h-5" />,
}
const WAVE_ACCENT: Record<number, string> = {
  1: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  2: 'border-blue-200 bg-blue-50 text-blue-700',
  3: 'border-amber-200 bg-amber-50 text-amber-700',
}
const SEV_COLOR: Record<string, string> = {
  Critical: 'bg-red-600 text-white', High: 'bg-red-100 text-red-700',
  Medium: 'bg-amber-100 text-amber-700', Low: 'bg-sky-100 text-sky-700',
  Informational: 'bg-slate-100 text-slate-600',
}

async function downloadCsv(url: string, filename: string) {
  const res = await fetch(url, { credentials: 'include' })
  if (!res.ok) return
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob); a.download = filename; a.click()
  URL.revokeObjectURL(a.href)
}

export function CleanupPlan() {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''
  const [plan, setPlan] = useState<Plan | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    getCleanupPlan(customerId || undefined)
      .then(setPlan).catch(() => setPlan(null)).finally(() => setLoading(false))
  }, [customerId])
  useEffect(() => { load() }, [load])

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Executive Cleanup Plan</h1>
          <p className="page-subtitle">
            Findings grouped into safe, sequenced cleanup waves with estimated risk reduction. Review-only — all changes require approved change management.
          </p>
        </div>
        <button onClick={() => downloadCsv(getCleanupTicketsUrl(customerId || undefined), 'cleanup_tickets.csv')}
          className="btn-secondary" disabled={!plan || plan.total_findings === 0}>
          <Download className="w-4 h-4" /> Export all tickets
        </button>
      </div>

      <div className="page-body">
        {loading ? (
          <div className="flex justify-center py-16"><div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" /></div>
        ) : !plan || plan.total_findings === 0 ? (
          <div className="card text-center py-12">
            <ListChecks className="w-10 h-10 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No actionable findings to plan. Run an analysis first.</p>
          </div>
        ) : (
          <>
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              <div className="card py-3"><p className="text-2xl font-bold text-gray-900">{plan.total_findings}</p><p className="text-xs text-gray-500">Actionable findings</p></div>
              <div className="card py-3"><p className="text-2xl font-bold text-gray-900">{plan.waves.reduce((s, w) => s + w.candidate_rule_count, 0)}</p><p className="text-xs text-gray-500">Candidate rules</p></div>
              <div className="card py-3"><p className="text-2xl font-bold text-gray-900">{plan.waves.reduce((s, w) => s + w.candidate_object_count, 0)}</p><p className="text-xs text-gray-500">Candidate objects</p></div>
              <div className="card py-3"><p className="text-2xl font-bold text-gray-900">{plan.total_risk_weight}</p><p className="text-xs text-gray-500">Total risk weight</p></div>
            </div>

            <div className="space-y-4">
              {plan.waves.map(w => (
                <div key={w.id} className="card">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className={`w-10 h-10 rounded-xl border flex items-center justify-center flex-shrink-0 ${WAVE_ACCENT[w.id]}`}>{WAVE_ICON[w.id]}</div>
                      <div>
                        <h2 className="text-base font-bold text-gray-900">Wave {w.id} · {w.name}</h2>
                        <p className="text-xs text-gray-500 mt-0.5 max-w-2xl">{w.description}</p>
                      </div>
                    </div>
                    <button onClick={() => downloadCsv(getCleanupTicketsUrl(customerId || undefined, w.id), `cleanup_tickets_wave${w.id}.csv`)}
                      className="btn-secondary py-1.5 px-3 text-xs flex-shrink-0" disabled={w.finding_count === 0}>
                      <Download className="w-3.5 h-3.5" /> Tickets
                    </button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                    <div><p className="text-xl font-bold text-gray-900">{w.finding_count}</p><p className="text-[11px] text-gray-500">Findings</p></div>
                    <div><p className="text-xl font-bold text-gray-900">{w.candidate_rule_count}</p><p className="text-[11px] text-gray-500">Candidate rules</p></div>
                    <div><p className="text-xl font-bold text-gray-900">{w.candidate_object_count}</p><p className="text-[11px] text-gray-500">Candidate objects</p></div>
                    <div>
                      <p className="text-xl font-bold text-emerald-600 flex items-center gap-1"><TrendingDown className="w-4 h-4" />{w.risk_reduction_pct}%</p>
                      <p className="text-[11px] text-gray-500">Est. risk reduction</p>
                    </div>
                  </div>

                  {/* Risk reduction bar */}
                  <div className="mt-3 h-2 bg-gray-100 rounded-full overflow-hidden">
                    <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${Math.min(100, w.risk_reduction_pct)}%` }} />
                  </div>

                  {/* Severity chips */}
                  {Object.keys(w.severity_breakdown).length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {(['Critical', 'High', 'Medium', 'Low', 'Informational'] as const).map(s =>
                        w.severity_breakdown[s] ? (
                          <span key={s} className={`text-[11px] font-semibold px-2 py-0.5 rounded ${SEV_COLOR[s]}`}>{w.severity_breakdown[s]} {s}</span>
                        ) : null,
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {plan.unscheduled_count > 0 && (
              <p className="text-xs text-gray-400 mt-4">
                {plan.unscheduled_count} informational/data-quality finding(s) are not part of a cleanup wave.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}
