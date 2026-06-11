import { useEffect, useState } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  CheckCircle2, AlertTriangle, TrendingUp, Shield,
  RefreshCw, FileText, BarChart2, ChevronRight, Info,
} from 'lucide-react'
import { getPolicies, getPolicyScorecard, reanalyzePolicy } from '../api/client'
import type { Policy, PolicyScorecard } from '../types'
import { clsx } from 'clsx'

// ── Grade ring ────────────────────────────────────────────────────────────────

function GradeRing({ score, grade }: { score: number; grade: string }) {
  const radius   = 54
  const circ     = 2 * Math.PI * radius
  const offset   = circ - (score / 100) * circ

  const gradeColor: Record<string, { ring: string; text: string; bg: string }> = {
    A: { ring: '#10b981', text: 'text-emerald-600', bg: 'bg-emerald-50' },
    B: { ring: '#3b82f6', text: 'text-blue-600',    bg: 'bg-blue-50'    },
    C: { ring: '#f59e0b', text: 'text-amber-600',   bg: 'bg-amber-50'   },
    D: { ring: '#f97316', text: 'text-orange-600',  bg: 'bg-orange-50'  },
    F: { ring: '#ef4444', text: 'text-red-600',     bg: 'bg-red-50'     },
  }
  const c = gradeColor[grade] || gradeColor['C']

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="10" />
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={c.ring}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-extrabold ${c.text}`}>{score}</span>
          <span className="text-[11px] text-gray-400 font-semibold uppercase tracking-wide">/ 100</span>
        </div>
      </div>
      <span className={clsx('mt-2 text-xl font-extrabold px-4 py-1 rounded-xl', c.bg, c.text)}>
        Grade {grade}
      </span>
    </div>
  )
}

// ── Dimension bar ─────────────────────────────────────────────────────────────

function DimensionBar({ label, score, weight, detail }: {
  label: string; score: number; weight: number; detail: string
}) {
  const color =
    score >= 80 ? 'bg-emerald-500' :
    score >= 60 ? 'bg-amber-400'   :
    score >= 40 ? 'bg-orange-500'  : 'bg-red-500'

  const textColor =
    score >= 80 ? 'text-emerald-700' :
    score >= 60 ? 'text-amber-700'   :
    score >= 40 ? 'text-orange-700'  : 'text-red-700'

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-gray-800">{label}</span>
          <span className="text-[10px] text-gray-400 border border-gray-200 rounded px-1">×{weight}%</span>
        </div>
        <span className={`font-bold text-sm ${textColor}`}>{score}</span>
      </div>
      <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <p className="text-xs text-gray-400">{detail}</p>
    </div>
  )
}

// ── Improvement row ───────────────────────────────────────────────────────────

function ImprovementRow({ label, severity }: { label: string; severity: string }) {
  const chip: Record<string, string> = {
    High:   'bg-red-100 text-red-700',
    Medium: 'bg-amber-100 text-amber-700',
    Low:    'bg-gray-100 text-gray-600',
  }
  return (
    <li className="flex items-start gap-3 py-2.5 border-b border-gray-50 last:border-0">
      <AlertTriangle className={clsx('w-4 h-4 mt-0.5 flex-shrink-0',
        severity === 'High' ? 'text-red-500' :
        severity === 'Medium' ? 'text-amber-500' : 'text-gray-400'
      )} />
      <span className="flex-1 text-sm text-gray-700">{label}</span>
      <span className={clsx('text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0', chip[severity] || chip.Low)}>
        {severity}
      </span>
    </li>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function Scorecard({ embedded }: { embedded?: boolean } = {}) {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''
  const [searchParams, setSearchParams] = useSearchParams()

  const [policies,        setPolicies]        = useState<Policy[]>([])
  const [selectedPolicy,  setSelectedPolicy]  = useState(searchParams.get('policy_id') || '')
  const [scorecard,       setScorecard]       = useState<PolicyScorecard | null>(null)
  const [loading,         setLoading]         = useState(false)
  const [loadingPolicies, setLoadingPolicies] = useState(true)
  const [reanalyzing,     setReanalyzing]     = useState(false)

  // load policy list
  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    getPolicies(pp)
      .then((data: unknown) => {
        const list: Policy[] = Array.isArray(data) ? data : []
        setPolicies(list.filter(p => p.analysis_status === 'completed'))
        if (!selectedPolicy && list.length === 1) setSelectedPolicy(list[0].id)
      })
      .finally(() => setLoadingPolicies(false))
  }, [customerId])

  // load scorecard when policy changes
  useEffect(() => {
    if (!selectedPolicy) { setScorecard(null); return }
    setLoading(true)
    setScorecard(null)
    getPolicyScorecard(selectedPolicy)
      .then(setScorecard)
      .finally(() => setLoading(false))

    const next = new URLSearchParams(searchParams)
    next.set('policy_id', selectedPolicy)
    setSearchParams(next, { replace: true })
  }, [selectedPolicy])

  const policy = policies.find(p => p.id === selectedPolicy)

  const handleReanalyze = async () => {
    if (!selectedPolicy) return
    setReanalyzing(true)
    await reanalyzePolicy(selectedPolicy)
    // poll until completed
    const poll = setInterval(async () => {
      const sc = await getPolicyScorecard(selectedPolicy).catch(() => null)
      if (sc) { setScorecard(sc); setReanalyzing(false); clearInterval(poll) }
    }, 3000)
    setTimeout(() => { clearInterval(poll); setReanalyzing(false) }, 60000)
  }

  return (
    <div>
      {/* ── Header ── */}
      {!embedded && (
        <div className="page-header sticky top-0 z-10">
          <div>
            <h1 className="page-title">Policy Hygiene Scorecard</h1>
            <p className="page-subtitle">
              Weighted hygiene score across logging, documentation, permissiveness, usage and object health
            </p>
          </div>
          {policy && (
            <div className="flex gap-2">
              <Link
                to={policy.customer_id
                  ? `/customers/${policy.customer_id}/findings?policy_id=${policy.id}`
                  : `/findings?policy_id=${policy.id}`}
                className="btn-secondary"
              >
                <BarChart2 className="w-4 h-4" /> Findings
              </Link>
              <button
                onClick={handleReanalyze}
                disabled={reanalyzing}
                className="btn-secondary"
              >
                <RefreshCw className={clsx('w-4 h-4', reanalyzing && 'animate-spin')} />
                {reanalyzing ? 'Analysing…' : 'Re-analyse'}
              </button>
            </div>
          )}
        </div>
      )}

      <div className={embedded ? '' : 'page-body max-w-5xl'}>

        {/* ── Policy selector ── */}
        {!loadingPolicies && policies.length > 1 && (
          <div className="card mb-6">
            <h2 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3">Select Policy</h2>
            <div className="flex flex-wrap gap-2">
              {policies.map(p => (
                <button
                  key={p.id}
                  onClick={() => setSelectedPolicy(p.id)}
                  className={clsx(
                    'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium transition-all',
                    selectedPolicy === p.id
                      ? 'border-blue-400 bg-blue-50 text-blue-700 ring-1 ring-blue-300'
                      : 'border-gray-200 bg-gray-50 text-gray-600 hover:border-gray-300 hover:bg-white'
                  )}
                >
                  <Shield className="w-3.5 h-3.5" />
                  {p.firewall_name}
                  {!customerId && p.customer_name ? <span className="text-gray-400">({p.customer_name})</span> : null}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ── No policy yet ── */}
        {!selectedPolicy && !loadingPolicies && (
          <div className="card empty-state py-16">
            <TrendingUp className="w-12 h-12 text-gray-200 mb-4" />
            <p className="text-lg font-semibold text-gray-500 mb-1">No policy selected</p>
            <p className="text-sm text-gray-400">
              {policies.length === 0
                ? 'No completed analyses found. Upload and analyse a policy first.'
                : 'Select a policy above to view its scorecard.'}
            </p>
          </div>
        )}

        {/* ── Loading spinner ── */}
        {loading && (
          <div className="flex justify-center py-20">
            <div className="animate-spin w-9 h-9 border-b-2 border-blue-600 rounded-full" />
          </div>
        )}

        {/* ── Scorecard ── */}
        {!loading && scorecard && (
          <div className="space-y-6">

            {/* Hero card */}
            <div className="card">
              <div className="flex flex-col md:flex-row items-center md:items-start gap-8">

                {/* Grade ring */}
                <div className="flex-shrink-0">
                  <GradeRing score={scorecard.score} grade={scorecard.grade} />
                </div>

                {/* Title + meta + read-only note */}
                <div className="flex-1 min-w-0">
                  <h2 className="text-xl font-extrabold text-gray-900 mb-1">
                    {scorecard.firewall_name} — Hygiene Score
                  </h2>
                  <p className="text-sm text-gray-500 mb-4">
                    {policy?.customer_name && <span>{policy.customer_name} · </span>}
                    {scorecard.vendor}
                    {policy?.policy_package ? ` · ${policy.policy_package}` : ''}
                  </p>

                  {/* Meta chips */}
                  <div className="flex flex-wrap gap-2 mb-4 text-xs">
                    {[
                      { label: 'Total Rules',   value: scorecard.meta.total_rules },
                      { label: 'Allow Rules',   value: scorecard.meta.allow_rules },
                      { label: 'Objects',       value: scorecard.meta.total_objects },
                      { label: 'Enabled Rules', value: scorecard.meta.enabled_rules },
                    ].map(m => (
                      <div key={m.label} className="bg-gray-50 border border-gray-100 rounded-lg px-3 py-1.5">
                        <span className="font-bold text-gray-800">{m.value}</span>
                        <span className="text-gray-400 ml-1">{m.label}</span>
                      </div>
                    ))}
                  </div>

                  {/* Read-only disclaimer */}
                  <div className="flex items-start gap-2 bg-orange-50 border border-orange-100 rounded-lg p-3 text-xs text-orange-800">
                    <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                    <span>
                      <strong>Read-only analysis.</strong> This scorecard identifies areas for improvement only.
                      Any remediation requires engineer validation and formal change approval.
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Two-column: Strengths + Improvements */}
            <div className="grid md:grid-cols-2 gap-6">

              {/* Strengths */}
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-6 h-6 rounded-md bg-emerald-100 flex items-center justify-center">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  </div>
                  <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide">Strengths</h3>
                </div>
                {scorecard.strengths.length === 0 ? (
                  <p className="text-sm text-gray-400 py-4 text-center">No strengths detected yet — run analysis first.</p>
                ) : (
                  <ul className="space-y-0">
                    {scorecard.strengths.map((s, i) => (
                      <li key={i} className="flex items-start gap-2.5 py-2 border-b border-gray-50 last:border-0">
                        <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                        <span className="text-sm text-gray-700">{s}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Improvements */}
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-6 h-6 rounded-md bg-amber-100 flex items-center justify-center">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                  </div>
                  <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide">Improvement Areas</h3>
                </div>
                {scorecard.improvements.length === 0 ? (
                  <p className="text-sm text-emerald-600 font-semibold py-4 text-center">✓ No improvement areas — excellent posture!</p>
                ) : (
                  <ul>
                    {scorecard.improvements.map((imp, i) => (
                      <ImprovementRow key={i} label={imp.label} severity={imp.severity} />
                    ))}
                  </ul>
                )}
              </div>
            </div>

            {/* Dimension breakdown */}
            <div className="card">
              <div className="flex items-center gap-2 mb-5">
                <div className="w-6 h-6 rounded-md bg-blue-100 flex items-center justify-center">
                  <BarChart2 className="w-4 h-4 text-blue-600" />
                </div>
                <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wide">Score Breakdown</h3>
                <span className="ml-auto text-xs text-gray-400">Weighted across 5 hygiene dimensions</span>
              </div>
              <div className="space-y-5">
                {scorecard.dimensions.map(d => (
                  <DimensionBar
                    key={d.key}
                    label={d.label}
                    score={d.score}
                    weight={d.weight}
                    detail={d.detail}
                  />
                ))}
              </div>
            </div>

            {/* Action links */}
            <div className="grid grid-cols-2 gap-4">
              <Link
                to={policy?.customer_id
                  ? `/customers/${policy.customer_id}/findings?policy_id=${selectedPolicy}`
                  : `/findings?policy_id=${selectedPolicy}`}
                className="card flex items-center gap-3 hover:border-blue-300 hover:shadow-md transition-all group"
              >
                <div className="w-8 h-8 rounded-lg bg-blue-50 flex items-center justify-center flex-shrink-0">
                  <BarChart2 className="w-4 h-4 text-blue-600" />
                </div>
                <div>
                  <p className="font-semibold text-gray-800 group-hover:text-blue-700 text-sm transition-colors">
                    View All Findings
                  </p>
                  <p className="text-xs text-gray-400">Detailed finding list with filters</p>
                </div>
                <ChevronRight className="w-4 h-4 text-gray-300 ml-auto" />
              </Link>

              <Link
                to={policy?.customer_id
                  ? `/customers/${policy.customer_id}/reports?policy_id=${selectedPolicy}`
                  : `/reports?policy_id=${selectedPolicy}`}
                className="card flex items-center gap-3 hover:border-blue-300 hover:shadow-md transition-all group"
              >
                <div className="w-8 h-8 rounded-lg bg-purple-50 flex items-center justify-center flex-shrink-0">
                  <FileText className="w-4 h-4 text-purple-600" />
                </div>
                <div>
                  <p className="font-semibold text-gray-800 group-hover:text-blue-700 text-sm transition-colors">
                    Generate Report
                  </p>
                  <p className="text-xs text-gray-400">Export HTML, Excel, CSV or JSON</p>
                </div>
                <ChevronRight className="w-4 h-4 text-gray-300 ml-auto" />
              </Link>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}
