/**
 * DeviceHistory — Tufin-style revision timeline + trend-based suggestions.
 * Shows each sync event with rule-change diffs, finding counts, and
 * trend analysis across all collected revisions.
 *
 * READ-ONLY: This page displays historical data only. No firewall changes are made.
 */
import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  History, ChevronDown, ChevronRight, PlusCircle, MinusCircle,
  RefreshCw, AlertTriangle, Shield, GitCompare, Clock, ArrowLeft,
  FileText, TrendingUp, TrendingDown, Lightbulb, Activity, Minus,
  AlertCircle, CheckCircle2, Info
} from 'lucide-react'
import { getRevisions, getRevision, getDevices, getDeviceTrends } from '../api/client'
import type { PolicyRevision, FirewallDeviceT, DeviceTrends, DeviceTrendSuggestion } from '../types'

// ── helpers ─────────────────────────────────────────────────────────────────

function fmtDateShort(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function delta(n: number | null, label: string, icon: React.ReactNode) {
  if (!n) return null
  return (
    <span className="flex items-center gap-1 text-xs font-semibold">
      {icon}
      {n > 0 ? '+' : ''}{n} {label}
    </span>
  )
}

// ── ChangeTypeBadge ──────────────────────────────────────────────────────────

function ChangeTypeBadge({ type }: { type: string }) {
  const styles: Record<string, string> = {
    added: 'bg-green-900/50 text-green-300 border border-green-700',
    removed: 'bg-red-900/50 text-red-300 border border-red-700',
    modified: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  }
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded font-mono uppercase ${styles[type] ?? 'bg-gray-700 text-gray-300'}`}>
      {type}
    </span>
  )
}

// ── SuggestionCard ───────────────────────────────────────────────────────────

function SuggestionCard({ s }: { s: DeviceTrendSuggestion }) {
  const sevCfg: Record<string, { cls: string; icon: React.ReactNode }> = {
    High:          { cls: 'border-red-700 bg-red-950/40',    icon: <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" /> },
    Medium:        { cls: 'border-orange-700 bg-orange-950/30', icon: <AlertCircle className="w-4 h-4 text-orange-400 shrink-0" /> },
    Low:           { cls: 'border-yellow-700 bg-yellow-950/30', icon: <Lightbulb className="w-4 h-4 text-yellow-400 shrink-0" /> },
    Informational: { cls: 'border-blue-800 bg-blue-950/30',   icon: <Info className="w-4 h-4 text-blue-400 shrink-0" /> },
  }
  const cfg = sevCfg[s.severity] ?? sevCfg.Informational

  const typeLabel: Record<string, string> = {
    persistent_zero_hits:     'Zero-Hit Persistence',
    frequently_modified:      'Unstable Rule',
    temporary_rule_removed:   'Temporary Rule',
    new_rule_with_findings:   'New Rule — Has Findings',
    finding_trend_increasing: 'Finding Count Rising',
    finding_trend_decreasing: 'Finding Count Falling',
    info:                     'Info',
  }

  return (
    <div className={`border rounded-lg p-3 space-y-1.5 ${cfg.cls}`}>
      <div className="flex items-start gap-2">
        {cfg.icon}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className="text-xs font-bold text-gray-200">{typeLabel[s.type] ?? s.type}</span>
            {s.rule_name && (
              <span className="font-mono text-xs text-gray-400 truncate max-w-[200px]" title={s.rule_name}>
                {s.rule_name}
              </span>
            )}
          </div>
          <p className="text-sm text-gray-300">{s.message}</p>
          {s.note && (
            <p className="text-xs text-gray-500 mt-1 italic flex items-center gap-1">
              <Shield className="w-3 h-3" /> {s.note}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Trend mini-chart (pure SVG sparkline) ────────────────────────────────────

function FindingSparkline({ data }: { data: Array<{ finding_count: number; high_finding_count: number; synced_at: string | null }> }) {
  if (data.length < 2) return null
  const W = 280, H = 60, PAD = 8
  const max = Math.max(...data.map(d => d.finding_count), 1)
  const pts = data.map((d, i) => ({
    x: PAD + (i / (data.length - 1)) * (W - PAD * 2),
    y: H - PAD - ((d.finding_count / max) * (H - PAD * 2)),
    hx: PAD + (i / (data.length - 1)) * (W - PAD * 2),
    hy: H - PAD - ((d.high_finding_count / max) * (H - PAD * 2)),
  }))
  const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const hpath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.hx.toFixed(1)} ${p.hy.toFixed(1)}`).join(' ')
  const first = data[0].finding_count, last = data[data.length - 1].finding_count
  const trend = last > first ? 'up' : last < first ? 'down' : 'flat'

  return (
    <div className="flex items-center gap-4">
      <svg width={W} height={H} className="flex-shrink-0">
        <path d={path} fill="none" stroke="#f97316" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d={hpath} fill="none" stroke="#ef4444" strokeWidth="1" strokeDasharray="3 2" strokeLinecap="round" strokeLinejoin="round" />
        {pts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#f97316" />
        ))}
      </svg>
      <div className="text-xs text-gray-400 space-y-1">
        <div className="flex items-center gap-1.5">
          <span className="w-4 h-0.5 bg-orange-500 inline-block" /> Total findings
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-4 h-0.5 bg-red-500 border-dashed inline-block" style={{ borderTopWidth: 1, borderStyle: 'dashed', background: 'none' }} /> High findings
        </div>
        <div className="flex items-center gap-1 mt-2">
          {trend === 'up' && <><TrendingUp className="w-3 h-3 text-red-400" /><span className="text-red-400">Increasing</span></>}
          {trend === 'down' && <><TrendingDown className="w-3 h-3 text-green-400" /><span className="text-green-400">Decreasing</span></>}
          {trend === 'flat' && <><Minus className="w-3 h-3 text-gray-400" /><span className="text-gray-400">Stable</span></>}
        </div>
      </div>
    </div>
  )
}

// ── RevisionRow ──────────────────────────────────────────────────────────────

function RevisionRow({ rev, isFirst }: { rev: PolicyRevision; isFirst: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const [detail, setDetail] = useState<PolicyRevision | null>(null)
  const [loading, setLoading] = useState(false)

  const hasChanges = (rev.rules_added ?? 0) + (rev.rules_removed ?? 0) + (rev.rules_modified ?? 0) > 0
  const hasFindings = (rev.finding_count ?? 0) > 0

  async function loadDetail() {
    if (detail) { setExpanded(e => !e); return }
    setLoading(true)
    try {
      const d = await getRevision(rev.id)
      setDetail(d)
      setExpanded(true)
    } finally {
      setLoading(false)
    }
  }

  const changeDetail = detail?.change_detail ?? []

  return (
    <div className={`border border-gray-700 rounded-lg overflow-hidden ${isFirst ? 'border-blue-600' : ''}`}>
      <button
        onClick={loadDetail}
        className="w-full flex items-start gap-3 p-4 hover:bg-gray-800/50 transition-colors text-left"
      >
        <div className="flex flex-col items-center pt-1 min-w-[24px]">
          <div className={`w-3 h-3 rounded-full border-2 ${isFirst ? 'bg-blue-500 border-blue-400' : 'bg-gray-600 border-gray-500'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="text-sm font-semibold text-gray-100">Revision #{rev.revision_number}</span>
            {isFirst && (
              <span className="text-xs bg-blue-900/60 text-blue-300 border border-blue-700 px-1.5 py-0.5 rounded">Latest</span>
            )}
            <span className="text-xs text-gray-500">{rev.sync_source === 'live_sync' ? '🔄 Live Sync' : '📤 Upload'}</span>
            <span className="text-xs text-gray-500 flex items-center gap-1">
              <Clock className="w-3 h-3" />{fmtDateShort(rev.synced_at)}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400">
            {rev.rule_count != null && (
              <span className="flex items-center gap-1"><FileText className="w-3 h-3" />{rev.rule_count} rules</span>
            )}
            {hasChanges && (
              <>
                {delta(rev.rules_added, 'added', <PlusCircle className="w-3 h-3 text-green-400" />)}
                {delta(rev.rules_removed, 'removed', <MinusCircle className="w-3 h-3 text-red-400" />)}
                {delta(rev.rules_modified, 'modified', <RefreshCw className="w-3 h-3 text-yellow-400" />)}
              </>
            )}
            {!hasChanges && rev.revision_number > 1 && (
              <span className="text-gray-600 italic">No rule changes</span>
            )}
            {hasFindings && (
              <span className="flex items-center gap-1 text-orange-400">
                <AlertTriangle className="w-3 h-3" />
                {rev.finding_count} findings
                {(rev.high_finding_count ?? 0) > 0 && (
                  <span className="text-red-400 font-semibold">({rev.high_finding_count} high)</span>
                )}
              </span>
            )}
          </div>
          {rev.change_summary && (
            <p className="text-xs text-gray-400 mt-1 italic">{rev.change_summary}</p>
          )}
        </div>
        <div className="flex items-center gap-1 text-gray-500 text-xs">
          {loading
            ? <RefreshCw className="w-4 h-4 animate-spin" />
            : changeDetail.length > 0 || !detail
              ? expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />
              : null
          }
        </div>
      </button>

      {expanded && detail && (
        <div className="border-t border-gray-700 bg-gray-900/40 p-4 space-y-3">
          {detail.policy_hash && (
            <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
              <GitCompare className="w-3 h-3" />
              Hash: {detail.policy_hash.substring(0, 16)}…
            </div>
          )}
          {changeDetail.length > 0 ? (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Rule Changes ({changeDetail.length})
              </p>
              <div className="overflow-x-auto rounded border border-gray-700">
                <table className="w-full text-xs">
                  <thead className="bg-gray-800 text-gray-400">
                    <tr>
                      <th className="px-3 py-2 text-left">Rule ID</th>
                      <th className="px-3 py-2 text-left">Change</th>
                      <th className="px-3 py-2 text-left">Name / Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {changeDetail.map((c, i) => (
                      <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/30">
                        <td className="px-3 py-2 font-mono text-gray-300">{c.rule_id}</td>
                        <td className="px-3 py-2"><ChangeTypeBadge type={c.change_type} /></td>
                        <td className="px-3 py-2 text-gray-400">
                          {c.change_type === 'added' && c.after && (
                            <span className="text-green-400">
                              {(c.after as Record<string, unknown>).name as string ?? c.rule_id} · {(c.after as Record<string, unknown>).action as string ?? ''}
                            </span>
                          )}
                          {c.change_type === 'removed' && c.before && (
                            <span className="text-red-400 line-through">
                              {(c.before as Record<string, unknown>).name as string ?? c.rule_id}
                            </span>
                          )}
                          {c.change_type === 'modified' && (
                            <span className="text-yellow-400">
                              {c.before ? `${(c.before as Record<string, unknown>).name as string ?? ''}` : ''}
                              {c.before && c.after ? ' (modified)' : ''}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-500 italic">No per-rule change detail for this revision.</p>
          )}
          {detail.policy_id && (
            <Link to={`/policies/${detail.policy_id}/rules`}
              className="text-xs text-blue-400 hover:underline flex items-center gap-1">
              <FileText className="w-3 h-3" /> View rulebase for this revision
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

// ── Trends tab ───────────────────────────────────────────────────────────────

function TrendsTab({ deviceId }: { deviceId: string }) {
  const [trends, setTrends] = useState<DeviceTrends | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    getDeviceTrends(deviceId)
      .then(setTrends)
      .catch(e => setError((e as Error).message ?? 'Failed to load trends'))
      .finally(() => setLoading(false))
  }, [deviceId])

  if (loading) return (
    <div className="flex items-center justify-center py-12 text-gray-500">
      <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading trend analysis…
    </div>
  )

  if (error) return (
    <div className="flex items-center gap-2 bg-red-950/40 border border-red-800 rounded-lg p-3 text-sm text-red-300">
      <AlertTriangle className="w-4 h-4 shrink-0" />{error}
    </div>
  )

  if (!trends) return null

  const highSuggestions = trends.suggestions.filter(s => s.severity === 'High')
  const otherSuggestions = trends.suggestions.filter(s => s.severity !== 'High')

  const intervalLabel = (h: number | null) => {
    if (!h) return 'Manual only'
    if (h >= 168) return 'Weekly'
    if (h >= 48) return `Every ${h / 24} days`
    return `Every ${h}h`
  }

  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-blue-400">{trends.revision_count}</div>
          <div className="text-xs text-gray-400 mt-0.5">Total Syncs</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-orange-400">{trends.suggestions.length}</div>
          <div className="text-xs text-gray-400 mt-0.5">Suggestions</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-red-400">{highSuggestions.length}</div>
          <div className="text-xs text-gray-400 mt-0.5">High Priority</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-purple-400">{intervalLabel(trends.sync_interval_hours)}</div>
          <div className="text-xs text-gray-400 mt-0.5">Sync Schedule</div>
        </div>
      </div>

      {/* Finding trend chart */}
      {trends.finding_trend.length >= 2 && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-400" /> Finding Count Over Time
          </h3>
          <FindingSparkline data={trends.finding_trend} />
          <div className="mt-3 flex flex-wrap gap-4 text-xs text-gray-500">
            {trends.finding_trend.map(p => (
              <span key={p.revision_number} className="text-center">
                <span className="text-orange-400 font-medium">{p.finding_count}</span>
                <br />
                <span className="text-gray-600">Rev #{p.revision_number}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Suggestions */}
      <div>
        <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-yellow-400" />
          Trend-Based Suggestions
          <span className="text-xs text-gray-500 font-normal ml-1">
            Based on {trends.revision_count} sync{trends.revision_count !== 1 ? 's' : ''}
          </span>
        </h3>

        {trends.suggestions.length === 0 ? (
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center">
            <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <p className="text-sm text-gray-300 font-medium">No trend concerns detected</p>
            <p className="text-xs text-gray-500 mt-1">
              {trends.revision_count < 2
                ? 'More syncs needed to detect trends. Enable auto-sync to collect data automatically.'
                : 'Policy appears stable across monitored syncs.'}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {trends.suggestions.map((s, i) => (
              <SuggestionCard key={i} s={s} />
            ))}
          </div>
        )}

        <p className="text-xs text-gray-600 mt-3 flex items-center gap-1">
          <Shield className="w-3 h-3" />
          All suggestions require engineer validation and change approval before any action is taken. This tool operates in read-only analysis mode.
        </p>
      </div>

      {/* Change activity table */}
      {trends.change_activity.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-yellow-400" /> Most Changed Rules
          </h3>
          <table className="w-full text-xs">
            <thead className="text-gray-400 border-b border-gray-700">
              <tr>
                <th className="pb-2 text-left">Rule</th>
                <th className="pb-2 text-right">Modifications</th>
                <th className="pb-2 text-right hidden md:table-cell">Last Changed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {trends.change_activity.map(ra => (
                <tr key={ra.rule_id} className="hover:bg-gray-700/30">
                  <td className="py-2 text-gray-300 font-medium">{ra.rule_name}
                    <span className="text-gray-600 font-mono ml-2 text-[10px]">#{ra.rule_id}</span>
                  </td>
                  <td className="py-2 text-right">
                    <span className="bg-yellow-900/50 text-yellow-300 border border-yellow-700 px-1.5 py-0.5 rounded font-bold">
                      ×{ra.modification_count}
                    </span>
                  </td>
                  <td className="py-2 text-right text-gray-500 hidden md:table-cell">
                    {ra.last_changed_at ? new Date(ra.last_changed_at).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export function DeviceHistory() {
  const { customerId, deviceId } = useParams<{ customerId: string; deviceId: string }>()
  const [device, setDevice] = useState<FirewallDeviceT | null>(null)
  const [revisions, setRevisions] = useState<PolicyRevision[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [limit, setLimit] = useState(20)
  const [activeTab, setActiveTab] = useState<'history' | 'trends'>('history')

  useEffect(() => {
    async function load() {
      setLoading(true)
      setError(null)
      try {
        if (deviceId) {
          const devices: FirewallDeviceT[] = await getDevices(customerId)
          const d = devices.find(x => x.id === deviceId) ?? null
          setDevice(d)
        }
        const revs = await getRevisions({ device_id: deviceId, limit })
        setRevisions(revs)
      } catch (e: unknown) {
        setError((e as Error).message ?? 'Failed to load revisions')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [deviceId, customerId, limit])

  const noChanges = revisions.filter(r =>
    (r.rules_added ?? 0) + (r.rules_removed ?? 0) + (r.rules_modified ?? 0) === 0
  ).length

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-gray-400">
        <Link to={`/customers/${customerId}`} className="hover:text-gray-200 transition-colors">Customer</Link>
        <ChevronRight className="w-4 h-4" />
        <Link to={`/customers/${customerId}/devices`} className="hover:text-gray-200 transition-colors">Live Devices</Link>
        <ChevronRight className="w-4 h-4" />
        <span className="text-gray-100">{device?.name ?? 'Device'} — History</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <History className="w-6 h-6 text-blue-400" />
            <h1 className="text-2xl font-bold text-gray-100">
              {device?.name ?? 'Device'} — Policy Monitoring
            </h1>
          </div>
          {device && (
            <p className="text-sm text-gray-400">
              {device.vendor} · {device.host}
              {device.vdom ? ` · ${device.vdom}` : ''}
              {device.sync_interval_hours
                ? <span className="ml-2 text-purple-400">· Auto-sync every {device.sync_interval_hours}h</span>
                : ''}
            </p>
          )}
        </div>
        <Link to={`/customers/${customerId}/devices`}
          className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-100 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Devices
        </Link>
      </div>

      {/* Read-only notice */}
      <div className="flex items-start gap-2 bg-blue-950/40 border border-blue-800/50 rounded-lg p-3 text-sm text-blue-300">
        <Shield className="w-4 h-4 mt-0.5 shrink-0 text-blue-400" />
        <span>
          <strong>Read-only view.</strong> This page shows historical policy snapshots and trend analysis.
          No firewall modifications are made. All suggestions require engineer validation and change approval before implementation.
        </span>
      </div>

      {/* Summary stats */}
      {revisions.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Syncs',    value: revisions.length,                           color: 'text-gray-100' },
            { label: 'With Changes',   value: revisions.length - noChanges,               color: 'text-yellow-400' },
            { label: 'Rules (latest)', value: revisions[0]?.rule_count ?? '—',            color: 'text-blue-400' },
            { label: 'High Findings',  value: revisions[0]?.high_finding_count ?? 0,      color: 'text-red-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-gray-400 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-700">
        {([
          { id: 'history', label: 'Revision History', icon: <History className="w-4 h-4" /> },
          { id: 'trends',  label: 'Trends & Suggestions', icon: <TrendingUp className="w-4 h-4" /> },
        ] as const).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab.icon}{tab.label}
          </button>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 bg-red-950/40 border border-red-800 rounded-lg p-3 text-sm text-red-300">
          <AlertTriangle className="w-4 h-4 shrink-0" />{error}
        </div>
      )}

      {/* Tab content */}
      {activeTab === 'trends' && deviceId && (
        <TrendsTab deviceId={deviceId} />
      )}

      {activeTab === 'history' && (
        <>
          {loading && (
            <div className="flex items-center justify-center py-12 text-gray-500">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading revision history…
            </div>
          )}

          {!loading && revisions.length === 0 && !error && (
            <div className="text-center py-12 text-gray-500">
              <History className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="font-medium">No revisions yet</p>
              <p className="text-sm mt-1">Sync the device to start tracking policy changes.</p>
              <Link to={`/customers/${customerId}/devices`}
                className="inline-flex items-center gap-1.5 mt-4 text-sm text-blue-400 hover:underline">
                <ArrowLeft className="w-3 h-3" /> Go to Devices to sync
              </Link>
            </div>
          )}

          {!loading && revisions.length > 0 && (
            <div className="space-y-2">
              {revisions.map((rev, i) => (
                <RevisionRow key={rev.id} rev={rev} isFirst={i === 0} />
              ))}
              {revisions.length >= limit && (
                <button onClick={() => setLimit(l => l + 20)}
                  className="w-full py-2 text-sm text-gray-400 hover:text-gray-200 border border-dashed border-gray-700 rounded-lg hover:border-gray-500 transition-colors">
                  Load more revisions
                </button>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
