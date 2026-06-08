/**
 * Policy Comparison (Before/After) Page
 * Shows a diff between two policy revisions using the existing revision data.
 * READ-ONLY: This page only displays analysis results — no firewall changes.
 */
import { useEffect, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft, ArrowRight, Plus, Minus, RefreshCw, Shield,
  AlertTriangle, TrendingDown, TrendingUp, Minus as MinusIcon,
  ChevronDown, ChevronUp,
} from 'lucide-react'
import { getRevisions, getRevision, getPolicies } from '../api/client'
import type { PolicyRevision, Policy } from '../types'

// ── Helpers ───────────────────────────────────────────────────────────────────

function RiskDelta({ before, after }: { before: number; after: number }) {
  const diff = after - before
  if (diff === 0) return <span className="text-gray-500 font-bold">{after}</span>
  if (diff < 0) return (
    <span className="text-green-700 font-bold flex items-center gap-1">
      <TrendingDown className="w-3.5 h-3.5" />{after} <span className="text-xs font-normal text-green-600">({diff})</span>
    </span>
  )
  return (
    <span className="text-red-700 font-bold flex items-center gap-1">
      <TrendingUp className="w-3.5 h-3.5" />{after} <span className="text-xs font-normal text-red-600">(+{diff})</span>
    </span>
  )
}

function StatDelta({
  label, before, after, positiveIsGood = false,
}: { label: string; before: number | null; after: number | null; positiveIsGood?: boolean }) {
  const b = before ?? 0
  const a = after ?? 0
  const diff = a - b
  const improved = positiveIsGood ? diff > 0 : diff < 0
  const worsened = positiveIsGood ? diff < 0 : diff > 0

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-4 text-center">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{label}</p>
      <div className="flex items-center justify-center gap-2">
        <span className="text-xl font-bold text-gray-400">{b}</span>
        <ArrowRight className="w-4 h-4 text-gray-300" />
        <span className={`text-2xl font-extrabold ${improved ? 'text-green-700' : worsened ? 'text-red-700' : 'text-gray-700'}`}>{a}</span>
      </div>
      {diff !== 0 && (
        <div className={`text-xs font-bold mt-1 flex items-center justify-center gap-0.5 ${improved ? 'text-green-600' : 'text-red-600'}`}>
          {diff > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {diff > 0 ? `+${diff}` : diff} {improved ? '(improved)' : '(worse)'}
        </div>
      )}
      {diff === 0 && <div className="text-xs text-gray-400 mt-1">No change</div>}
    </div>
  )
}

function ChangeTypeBadge({ type }: { type: string }) {
  const cfg: Record<string, string> = {
    added: 'bg-green-100 text-green-700 border-green-300',
    removed: 'bg-red-100 text-red-700 border-red-300',
    modified: 'bg-amber-100 text-amber-700 border-amber-300',
  }
  const icon: Record<string, React.ReactNode> = {
    added: <Plus className="w-2.5 h-2.5" />,
    removed: <Minus className="w-2.5 h-2.5" />,
    modified: <RefreshCw className="w-2.5 h-2.5" />,
  }
  return (
    <span className={`flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${cfg[type] || 'bg-gray-100 text-gray-600 border-gray-300'}`}>
      {icon[type]}{type}
    </span>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export function PolicyComparison() {
  const { policyId } = useParams<{ policyId: string }>()

  const [revisions, setRevisions] = useState<PolicyRevision[]>([])
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [beforeRev, setBeforeRev] = useState<PolicyRevision | null>(null)
  const [afterRev, setAfterRev] = useState<PolicyRevision | null>(null)
  const [beforeId, setBeforeId] = useState('')
  const [afterId, setAfterId] = useState('')
  const [loading, setLoading] = useState(true)
  const [comparing, setComparing] = useState(false)
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (!policyId) return
    Promise.all([
      getRevisions({ policy_id: policyId, limit: 20 }),
      getPolicies({ id: policyId }).catch(() => []),
    ]).then(([revs, policies]) => {
      const revList: PolicyRevision[] = Array.isArray(revs) ? revs : (revs.revisions || [])
      setRevisions(revList)
      if (Array.isArray(policies) && policies.length > 0) setPolicy(policies[0])
      // Auto-select: oldest as "before", newest as "after"
      if (revList.length >= 2) {
        setBeforeId(revList[revList.length - 1].id)
        setAfterId(revList[0].id)
      }
    }).finally(() => setLoading(false))
  }, [policyId])

  const compare = useCallback(async () => {
    if (!beforeId || !afterId || beforeId === afterId) return
    setComparing(true)
    try {
      const [b, a] = await Promise.all([getRevision(beforeId), getRevision(afterId)])
      setBeforeRev(b)
      setAfterRev(a)
    } finally {
      setComparing(false)
    }
  }, [beforeId, afterId])

  useEffect(() => {
    if (beforeId && afterId) compare()
  }, [compare])

  const toggleRule = (id: string) => {
    setExpandedRules(prev => {
      const s = new Set(prev)
      s.has(id) ? s.delete(id) : s.add(id)
      return s
    })
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-700" />
    </div>
  )

  if (revisions.length === 0) return (
    <div className="p-8">
      <Link to={policyId ? `/policies/${policyId}/rules` : '/policies'} className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1 mb-6">
        <ArrowLeft className="w-4 h-4" /> Back to Rulebase
      </Link>
      <div className="card text-center py-16">
        <Shield className="w-12 h-12 text-gray-300 mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-gray-700 mb-2">No revisions yet</h2>
        <p className="text-gray-500 text-sm">
          Policy comparisons become available after a second policy import or sync.<br />
          Upload a new policy export to track changes over time.
        </p>
      </div>
    </div>
  )

  const changeDetail = afterRev?.change_detail || []
  const added = changeDetail.filter(c => c.change_type === 'added')
  const removed = changeDetail.filter(c => c.change_type === 'removed')
  const modified = changeDetail.filter(c => c.change_type === 'modified')

  const beforeName = revisions.find(r => r.id === beforeId)
  const afterName = revisions.find(r => r.id === afterId)

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <Link to={policyId ? `/policies/${policyId}/rules` : '/policies'}
          className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1">
          <ArrowLeft className="w-4 h-4" /> Back
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Policy Comparison</h1>
          {policy && <p className="text-gray-500 text-sm mt-0.5">{policy.firewall_name} · {policy.vendor}</p>}
        </div>
      </div>

      {/* Read-only disclaimer */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl px-4 py-3 mb-6 flex items-start gap-3">
        <Shield className="w-4 h-4 text-blue-600 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-blue-700">
          <strong>Read-only analysis.</strong> This comparison is generated from uploaded policy exports.
          It does not reflect or initiate any changes to the live firewall.
          Any remediation must be validated by the responsible team and implemented through the approved change management process.
        </p>
      </div>

      {/* Revision selector */}
      <div className="card mb-6">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Select Revisions to Compare</h3>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="block text-xs font-bold text-gray-500 uppercase mb-1">Before (Baseline)</label>
            <select
              value={beforeId}
              onChange={e => setBeforeId(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select baseline revision…</option>
              {revisions.map(r => (
                <option key={r.id} value={r.id}>
                  Rev #{r.revision_number} — {r.synced_at ? new Date(r.synced_at).toLocaleString() : 'Unknown date'}
                  {r.rule_count != null ? ` (${r.rule_count} rules)` : ''}
                </option>
              ))}
            </select>
          </div>
          <ArrowRight className="w-5 h-5 text-gray-400 flex-shrink-0 mt-5" />
          <div className="flex-1">
            <label className="block text-xs font-bold text-gray-500 uppercase mb-1">After (Current)</label>
            <select
              value={afterId}
              onChange={e => setAfterId(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select target revision…</option>
              {revisions.map(r => (
                <option key={r.id} value={r.id}>
                  Rev #{r.revision_number} — {r.synced_at ? new Date(r.synced_at).toLocaleString() : 'Unknown date'}
                  {r.rule_count != null ? ` (${r.rule_count} rules)` : ''}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {comparing && (
        <div className="flex justify-center py-8">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600" />
        </div>
      )}

      {!comparing && beforeRev && afterRev && (
        <div className="space-y-6">

          {/* Summary stats */}
          <div>
            <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-3">
              Summary — Rev #{beforeRev.revision_number} → Rev #{afterRev.revision_number}
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
              <StatDelta label="Total Rules" before={beforeRev.rule_count} after={afterRev.rule_count} positiveIsGood={false} />
              <StatDelta label="Findings" before={beforeRev.finding_count} after={afterRev.finding_count} positiveIsGood={false} />
              <StatDelta label="High Findings" before={beforeRev.high_finding_count} after={afterRev.high_finding_count} positiveIsGood={false} />
              <StatDelta label="Objects" before={beforeRev.object_count} after={afterRev.object_count} positiveIsGood={false} />
            </div>

            {/* Rules added/removed/modified summary */}
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Plus className="w-5 h-5 text-green-600" />
                  <span className="text-3xl font-extrabold text-green-700">{afterRev.rules_added ?? added.length}</span>
                </div>
                <p className="text-xs font-semibold text-green-700 uppercase">Rules Added</p>
              </div>
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <Minus className="w-5 h-5 text-red-600" />
                  <span className="text-3xl font-extrabold text-red-700">{afterRev.rules_removed ?? removed.length}</span>
                </div>
                <p className="text-xs font-semibold text-red-700 uppercase">Rules Removed</p>
              </div>
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-center">
                <div className="flex items-center justify-center gap-2 mb-1">
                  <RefreshCw className="w-5 h-5 text-amber-600" />
                  <span className="text-3xl font-extrabold text-amber-700">{afterRev.rules_modified ?? modified.length}</span>
                </div>
                <p className="text-xs font-semibold text-amber-700 uppercase">Rules Modified</p>
              </div>
            </div>
          </div>

          {/* Change summary text */}
          {afterRev.change_summary && (
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Change Summary</h3>
              <p className="text-sm text-gray-600">{afterRev.change_summary}</p>
            </div>
          )}

          {/* Detailed rule changes */}
          {changeDetail.length > 0 && (
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-700 mb-4">
                Rule-Level Changes ({changeDetail.length})
              </h3>
              <div className="space-y-2">
                {changeDetail.map((c, i) => {
                  const isExpanded = expandedRules.has(c.rule_id)
                  const hasDetail = (c.before || c.after) && Object.keys(c.before || c.after || {}).length > 0
                  return (
                    <div key={i} className={`border rounded-lg overflow-hidden ${
                      c.change_type === 'added' ? 'border-green-200' :
                      c.change_type === 'removed' ? 'border-red-200' :
                      'border-amber-200'
                    }`}>
                      <div
                        className={`flex items-center gap-3 px-3 py-2.5 ${hasDetail ? 'cursor-pointer hover:bg-gray-50' : ''} ${
                          c.change_type === 'added' ? 'bg-green-50' :
                          c.change_type === 'removed' ? 'bg-red-50' :
                          'bg-amber-50'
                        }`}
                        onClick={() => hasDetail && toggleRule(c.rule_id)}
                      >
                        <ChangeTypeBadge type={c.change_type} />
                        <span className="text-sm font-medium text-gray-800 flex-1">{c.rule_id}</span>
                        {hasDetail && (
                          isExpanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />
                        )}
                      </div>
                      {isExpanded && hasDetail && (
                        <div className="grid grid-cols-2 gap-0 divide-x divide-gray-200 bg-white">
                          <div className="p-3">
                            <p className="text-[10px] font-bold text-gray-400 uppercase mb-1.5">Before</p>
                            {c.before ? (
                              <pre className="text-[10px] text-gray-600 whitespace-pre-wrap font-mono">
                                {JSON.stringify(c.before, null, 2)}
                              </pre>
                            ) : <p className="text-xs text-gray-400 italic">—</p>}
                          </div>
                          <div className="p-3">
                            <p className="text-[10px] font-bold text-gray-400 uppercase mb-1.5">After</p>
                            {c.after ? (
                              <pre className="text-[10px] text-gray-600 whitespace-pre-wrap font-mono">
                                {JSON.stringify(c.after, null, 2)}
                              </pre>
                            ) : <p className="text-xs text-gray-400 italic">—</p>}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Notes section */}
          <div className="bg-gray-50 border border-gray-200 rounded-xl px-4 py-3 text-xs text-gray-500">
            <p className="font-semibold text-gray-600 mb-1">Comparison Notes</p>
            <ul className="space-y-0.5 list-disc list-inside">
              <li>This comparison shows structural differences between uploaded policy exports.</li>
              <li>Findings counts are based on the analysis run at the time of each import.</li>
              <li>Rule changes are detected from the revision metadata. Detailed diffs require live sync with change tracking.</li>
              <li>All changes shown are for review purposes only. This tool does not modify or push any firewall configuration.</li>
            </ul>
          </div>
        </div>
      )}

      {!comparing && revisions.length === 1 && (
        <div className="card text-center py-12 text-gray-400">
          <RefreshCw className="w-10 h-10 mx-auto mb-3 text-gray-300" />
          <p className="font-medium">Only one revision available</p>
          <p className="text-sm mt-1">Upload or sync a new policy version to enable comparison.</p>
        </div>
      )}
    </div>
  )
}
