import { useEffect, useState, useCallback } from 'react'
import { useSearchParams, useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  ChevronDown, ChevronUp, MessageSquare, Check, Filter,
  CheckSquare, Square, AlertTriangle, Shield, Clock, Copy,
  Eye, EyeOff, Layers, ZapOff, Wifi, Activity, Download, X,
  Send, User, FileText, Search,
} from 'lucide-react'
import {
  getFindings, updateFinding, bulkUpdateFindings, getPolicies, getRemediation, type Remediation,
  addFindingComment, getFindingComments, getFindingsExportUrl,
} from '../api/client'
import { SeverityBadge, StatusBadge, ConfidenceBadge } from '../components/ui/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/page-state'
import { DetailDrawer } from '../components/ui/DetailDrawer'
import { useAuth } from '../contexts/AuthContext'
import type { Finding, Policy, AffectedRuleData, FindingComment } from '../types'
import { fetchFailureMessage, friendlyErrorMessage } from '../utils/errors'

/** Backend stores array fields as JSON strings in SQLite — handle both formats. */
function parseArr(v: unknown): string[] {
  if (Array.isArray(v)) return v as string[]
  if (typeof v === 'string' && v.trim().startsWith('[')) {
    try { return JSON.parse(v) } catch { /* fall through */ }
  }
  if (typeof v === 'string' && v.length > 0) return [v]
  return []
}

// ── Constants ─────────────────────────────────────────────────────────────────

const FINDING_TYPES: Record<string, string> = {
  // Core rule analysis
  duplicate_rule: 'Duplicate Rule',
  shadowed_rule: 'Shadowed Rule',
  same_action_shadowed_rule: 'Redundant Rule',
  conflicting_shadowed_rule: 'Conflicting Shadowed Rule',
  partial_shadowed_rule: 'Partially Shadowed Rule',
  inoperative_rule: 'Inoperative Rule',
  shadowing_not_evaluated: 'Shadowing Not Evaluated',
  // Application control
  rule_without_app_controls: 'No App Controls',
  palo_alto_port_based_rule_candidate: 'Port-Based Rule',
  risky_application_allowed: 'Risky Application',
  fortigate_security_profile_gap: 'No Security Profiles',
  application_analysis_not_supported_for_vendor: 'App Analysis N/A',
  application_data_unavailable: 'App Data Unavailable',
  disabled_rule: 'Disabled Rule',
  zero_hit_rule: 'Zero Hits',
  low_usage_rule: 'Low Usage',
  overly_permissive: 'Overly Permissive',
  risky_service: 'Risky Service',
  no_logging: 'No Logging',
  no_documentation: 'No Documentation',
  temporary_rule: 'Temporary Rule',
  // Advanced rule analysis
  naming_quality: 'Poor Rule Name',
  expired_rule: 'Expired Schedule',
  nat_complexity: 'NAT Rule',
  vpn_access: 'Broad VPN Access',
  negated_object: 'Negated Object',
  // Exposure
  rdp_exposed: 'RDP Exposed',
  ssh_exposed: 'SSH Exposed',
  database_exposed: 'Database Exposed',
  cleartext_service: 'Cleartext Protocol',
  inbound_from_internet: 'Inbound From Internet',
  lateral_movement_risk: 'Lateral Movement Risk',
  // Policy structure
  mergeable_rules: 'Consolidation Candidate',
  no_cleanup_rule: 'Missing Cleanup Rule',
  rule_order_optimization: 'Rule Order Optimization',
  large_rule_section: 'Oversized Section',
  // Object analysis
  unattached_object: 'Unattached Object',
  object_usage_unknown: 'Object Usage Unknown',
  unused_object: 'Unused Object',
  duplicate_object: 'Duplicate Object',
  empty_group: 'Empty Group',
  large_group: 'Large Group',
  broad_network: 'Broad Network',
  service_range: 'Large Port Range',
  // Import / data quality
  import_quality: 'Import Quality',
}

const FINDING_ICONS: Record<string, React.ReactNode> = {
  shadowed_rule: <Layers className="w-3.5 h-3.5" />,
  duplicate_rule: <Copy className="w-3.5 h-3.5" />,
  zero_hit_rule: <ZapOff className="w-3.5 h-3.5" />,
  overly_permissive: <AlertTriangle className="w-3.5 h-3.5" />,
  disabled_rule: <EyeOff className="w-3.5 h-3.5" />,
  no_logging: <Eye className="w-3.5 h-3.5" />,
  risky_service: <Wifi className="w-3.5 h-3.5" />,
  low_usage_rule: <Activity className="w-3.5 h-3.5" />,
  import_quality: <FileText className="w-3.5 h-3.5" />,
  rdp_exposed: <Shield className="w-3.5 h-3.5" />,
  ssh_exposed: <Shield className="w-3.5 h-3.5" />,
  database_exposed: <Shield className="w-3.5 h-3.5" />,
  cleartext_service: <Wifi className="w-3.5 h-3.5" />,
  mergeable_rules: <Copy className="w-3.5 h-3.5" />,
  no_cleanup_rule: <Shield className="w-3.5 h-3.5" />,
  lateral_movement_risk: <AlertTriangle className="w-3.5 h-3.5" />,
  inbound_from_internet: <Shield className="w-3.5 h-3.5" />,
  rule_order_optimization: <Activity className="w-3.5 h-3.5" />,
  large_rule_section: <Layers className="w-3.5 h-3.5" />,
}

// Full spec-aligned status list (Section 15)
const STATUSES = [
  'New',
  'Review Required',
  'In Review',
  'Requires Business Validation',
  'Requires Customer Confirmation',
  'Confirmed Cleanup Candidate',
  'Manual Change Required',
  'Change Planned Outside Tool',
  'Cleanup Completed Outside Tool',
  'False Positive',
  'Accepted Risk',
  'Deferred',
  'Reopened',
]

const PRIORITIES = ['Immediate', 'High', 'Standard', 'Low', 'Monitor']

const PRIORITY_COLORS: Record<string, string> = {
  Immediate: 'bg-red-100 text-red-700 border-red-300',
  High: 'bg-orange-100 text-orange-700 border-orange-300',
  Standard: 'bg-blue-100 text-blue-700 border-blue-300',
  Low: 'bg-gray-100 text-gray-600 border-gray-300',
  Monitor: 'bg-purple-100 text-purple-600 border-purple-300',
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'bg-red-600 text-white border-red-700',
  High: 'bg-red-100 text-red-700 border-red-200',
  Medium: 'bg-amber-100 text-amber-700 border-amber-200',
  Low: 'bg-sky-100 text-sky-700 border-sky-200',
  Informational: 'bg-slate-100 text-slate-600 border-slate-200',
}

// Quick preset filters
const PRESETS = [
  { label: '🛑 Critical Severity', params: { severity: 'Critical' } },
  { label: '🔴 High Severity', params: { severity: 'High' } },
  { label: '⚡ Zero-Hit Rules', params: { finding_type: 'zero_hit_rule' } },
  { label: '🔓 Overly Permissive', params: { finding_type: 'overly_permissive' } },
  { label: '👥 Shadowed Rules', params: { finding_type: 'shadowed_rule' } },
  { label: '📋 Needs Review', params: { status: 'Review Required' } },
  { label: '✅ Cleanup Candidates', params: { status: 'Confirmed Cleanup Candidate' } },
  { label: '📝 No Documentation', params: { finding_type: 'no_documentation' } },
  { label: '🌐 Broad VPN Access', params: { finding_type: 'vpn_access' } },
  { label: '📦 Empty Groups', params: { finding_type: 'empty_group' } },
  { label: '🌍 Broad Networks', params: { finding_type: 'broad_network' } },
  { label: '🏷️ Poor Names', params: { finding_type: 'naming_quality' } },
]

// ── Rule Card ─────────────────────────────────────────────────────────────────

function ValueList({ values, highlight }: { values: unknown; highlight?: boolean }) {
  const arr = parseArr(values)
  if (arr.length === 0) return <span className="text-gray-400 italic text-xs">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {arr.slice(0, 6).map((v, i) => {
        const isAny = ['any', 'all', '*'].includes(String(v).toLowerCase().trim())
        return (
          <span
            key={i}
            className={`px-1.5 py-0.5 rounded text-xs font-mono
              ${isAny && highlight
                ? 'bg-red-100 text-red-700 border border-red-300 font-bold'
                : 'bg-gray-100 text-gray-700 border border-gray-200'}`}
          >
            {v}
          </span>
        )
      })}
      {arr.length > 6 && (
        <span className="text-xs text-gray-400 self-center">+{arr.length - 6} more</span>
      )}
    </div>
  )
}

function ActionBadge({ action }: { action: string | null }) {
  if (!action) return <span className="text-gray-400 text-xs">—</span>
  const a = action.toLowerCase()
  const cls = a === 'accept' || a === 'allow' || a === 'permit'
    ? 'bg-green-100 text-green-700 border-green-300'
    : a === 'deny' || a === 'drop' || a === 'reject' || a === 'block'
      ? 'bg-red-100 text-red-700 border-red-300'
      : 'bg-gray-100 text-gray-700 border-gray-200'
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${cls}`}>
      {action}
    </span>
  )
}

function RuleCard({
  rule,
  badge,
  badgeColor,
  highlightPermissive,
  showZeroHit,
}: {
  rule: AffectedRuleData
  badge?: string
  badgeColor?: string
  highlightPermissive?: boolean
  showZeroHit?: boolean
}) {
  const hitZero = rule.hit_count === 0 || rule.hit_count === null

  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden bg-white shadow-sm">
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-200">
        <div className="flex items-center gap-2 min-w-0">
          {rule.rule_number != null && (
            <span className="text-xs font-mono text-gray-400 flex-shrink-0">#{rule.rule_number}</span>
          )}
          <span className="text-sm font-semibold text-gray-900 truncate">{rule.rule_name}</span>
          {rule.section && (
            <span className="text-xs text-gray-400 truncate hidden sm:inline">· {rule.section}</span>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {badge && (
            <span className={`px-2 py-0.5 rounded text-xs font-bold border ${badgeColor || 'bg-gray-100 text-gray-600 border-gray-300'}`}>
              {badge}
            </span>
          )}
          {!rule.enabled && (
            <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-100 text-gray-500 border border-gray-300">
              DISABLED
            </span>
          )}
          <ActionBadge action={rule.action} />
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-0 divide-x divide-gray-100">
        <div className="px-3 py-2.5">
          <div className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-1.5">Source</div>
          <ValueList values={rule.sources} highlight={highlightPermissive} />
        </div>
        <div className="px-3 py-2.5">
          <div className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-1.5">Destination</div>
          <ValueList values={rule.destinations} highlight={highlightPermissive} />
        </div>
        <div className="px-3 py-2.5">
          <div className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-1.5">Service / Port</div>
          <ValueList values={rule.services} highlight={highlightPermissive} />
        </div>
        <div className="px-3 py-2.5">
          <div className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-1.5">Hit Count</div>
          {showZeroHit ? (
            <div>
              <span className={`text-sm font-bold ${hitZero ? 'text-red-600' : 'text-gray-700'}`}>
                {rule.hit_count ?? 0}
              </span>
              {rule.last_hit ? (
                <div className="text-xs text-gray-400 mt-0.5">Last: {rule.last_hit}</div>
              ) : (
                <div className="text-xs text-red-400 mt-0.5 font-medium">Never hit</div>
              )}
            </div>
          ) : (
            <span className="text-sm font-medium text-gray-700">
              {rule.hit_count ?? <span className="text-gray-400 italic">N/A</span>}
            </span>
          )}
        </div>
      </div>

      {(rule.comments || !rule.logging_enabled || parseArr(rule.applications).length > 0) && (
        <div className="flex flex-wrap items-center gap-3 px-4 py-2 bg-gray-50 border-t border-gray-100 text-xs text-gray-500">
          {!rule.logging_enabled && (
            <span className="flex items-center gap-1 text-amber-600">
              <Eye className="w-3 h-3" /> Logging disabled
            </span>
          )}
          {(() => { const apps = parseArr(rule.applications); return apps.length > 0 && (
            <span>Apps: {apps.slice(0, 3).join(', ')}{apps.length > 3 ? '…' : ''}</span>
          )})()}
          {rule.comments && (
            <span className="text-gray-400 italic truncate max-w-[300px]">"{rule.comments}"</span>
          )}
        </div>
      )}
    </div>
  )
}

// ── Affected Rules Panel ──────────────────────────────────────────────────────

function AffectedRulesPanel({ finding }: { finding: Finding }) {
  const rules = finding.affected_rules_data || []
  if (rules.length === 0) return null
  const type = finding.finding_type

  if (type === 'shadowed_rule' && rules.length >= 2) {
    const shadowed = rules[0]
    const shadowing = rules[1]
    return (
      <div>
        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
          <Layers className="w-3.5 h-3.5" /> Shadow Analysis
        </h4>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <div className="text-xs font-bold text-red-600 uppercase tracking-wide mb-2 flex items-center gap-1.5">
              <Shield className="w-3 h-3" /> Shadowing Rule
              <span className="text-gray-400 font-normal normal-case">(takes priority — matches first)</span>
            </div>
            <RuleCard rule={shadowing} badge="SHADOWING" badgeColor="bg-red-100 text-red-700 border-red-300" />
          </div>
          <div>
            <div className="text-xs font-bold text-orange-600 uppercase tracking-wide mb-2 flex items-center gap-1.5">
              <EyeOff className="w-3 h-3" /> Shadowed Rule
              <span className="text-gray-400 font-normal normal-case">(never reached — dead rule)</span>
            </div>
            <RuleCard rule={shadowed} badge="SHADOWED" badgeColor="bg-orange-100 text-orange-700 border-orange-300" />
          </div>
        </div>
        <p className="text-xs text-gray-400 mt-2 italic">
          The shadowed rule will never match traffic. Both rules are shown read-only.
          Any changes require engineer validation and change approval.
        </p>
      </div>
    )
  }

  if (type === 'duplicate_rule' && rules.length >= 2) {
    return (
      <div>
        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
          <Copy className="w-3.5 h-3.5" /> Duplicate Rule Group ({rules.length} rules)
        </h4>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {rules.map((rule, i) => (
            <div key={rule.id}>
              <div className="text-xs font-bold text-purple-600 uppercase tracking-wide mb-2">
                {i === 0 ? 'Reference rule' : `Duplicate match ${i}`}
              </div>
              <RuleCard
                rule={rule}
                badge={i === 0 ? 'REFERENCE' : 'DUPLICATE'}
                badgeColor={i === 0 ? 'bg-purple-100 text-purple-700 border-purple-300' : 'bg-gray-100 text-gray-600 border-gray-300'}
              />
            </div>
          ))}
        </div>
        <p className="text-xs text-gray-400 mt-2 italic">
          These rules match the same effective traffic. Review each to confirm whether
          it is still required; any consolidation requires engineer validation and
          change approval.
        </p>
      </div>
    )
  }

  if (type === 'zero_hit_rule') {
    return (
      <div>
        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
          <ZapOff className="w-3.5 h-3.5" /> Zero-Hit Rules
        </h4>
        <div className="space-y-3">
          {rules.map(rule => <RuleCard key={rule.id} rule={rule} showZeroHit />)}
        </div>
        <p className="text-xs text-gray-400 mt-2 italic">
          Rules with no recorded hits may be obsolete or misconfigured. Removal requires engineer validation and change approval.
        </p>
      </div>
    )
  }

  if (type === 'overly_permissive') {
    return (
      <div>
        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5" /> Overly Permissive Rules
          <span className="text-xs font-normal text-gray-400">"Any" fields highlighted in red</span>
        </h4>
        <div className="space-y-3">
          {rules.map(rule => <RuleCard key={rule.id} rule={rule} highlightPermissive showZeroHit={false} />)}
        </div>
        <p className="text-xs text-gray-400 mt-2 italic">
          Tightening requires engineer validation and change approval.
        </p>
      </div>
    )
  }

  return (
    <div>
      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
        {FINDING_ICONS[type] || <Shield className="w-3.5 h-3.5" />}
        Affected Rules ({rules.length})
      </h4>
      <div className="space-y-3">
        {rules.map((rule, i) => (
          <RuleCard
            key={rule.id}
            rule={rule}
            badge={rules.length > 1 ? `Rule ${i + 1}` : undefined}
            showZeroHit={type === 'low_usage_rule'}
            highlightPermissive={type === 'risky_service'}
          />
        ))}
      </div>
      <p className="text-xs text-gray-400 mt-2 italic">
        Rules shown are read-only. Any remediation requires engineer validation and change approval.
      </p>
    </div>
  )
}

// ── Evidence Box ──────────────────────────────────────────────────────────────

function EvidenceBox({ evidence }: { evidence: Record<string, unknown> }) {
  return (
    <div className="bg-gray-900 rounded-lg p-3 overflow-x-auto mt-2">
      <pre className="text-xs text-green-300 whitespace-pre-wrap">
        {JSON.stringify(evidence, null, 2)}
      </pre>
    </div>
  )
}

// ── Comment Thread ────────────────────────────────────────────────────────────

function CommentThread({ findingId }: { findingId: string }) {
  const [comments, setComments] = useState<FindingComment[]>([])
  const [text, setText] = useState('')
  const [sending, setSending] = useState(false)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    getFindingComments(findingId)
      .then(setComments)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [findingId])

  useEffect(() => { load() }, [load])

  const send = async () => {
    if (!text.trim()) return
    setSending(true)
    try {
      await addFindingComment(findingId, text.trim())
      setText('')
      load()
    } finally {
      setSending(false)
    }
  }

  const statusChanged = (c: FindingComment) => c.old_status && c.new_status && c.old_status !== c.new_status

  return (
    <div>
      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
        <MessageSquare className="w-3.5 h-3.5" /> Activity &amp; Comments
      </h4>

      {loading ? (
        <div className="py-3 text-center text-xs text-gray-400">Loading…</div>
      ) : comments.length === 0 ? (
        <p className="text-xs text-gray-400 italic mb-3">No comments yet. Add one below.</p>
      ) : (
        <div className="space-y-2 mb-3 max-h-56 overflow-y-auto pr-1">
          {comments.map(c => (
            <div key={c.id} className="flex gap-2.5">
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-100 flex items-center justify-center">
                <User className="w-3 h-3 text-brand-600" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-xs font-semibold text-gray-700 capitalize">{c.author}</span>
                  <span className="text-[10px] text-gray-400">
                    {c.created_at ? new Date(c.created_at).toLocaleString() : ''}
                  </span>
                  {statusChanged(c) && (
                    <span className="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded font-medium">
                      {c.old_status} → {c.new_status}
                    </span>
                  )}
                </div>
                {c.comment && (
                  <p className="text-xs text-gray-600 leading-relaxed">{c.comment}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* New comment input */}
      <div className="flex gap-2 items-start">
        <div className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center mt-0.5">
          <User className="w-3 h-3 text-gray-500" />
        </div>
        <div className="flex-1 flex gap-2">
          <input
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
            onClick={e => e.stopPropagation()}
            placeholder="Add a comment or note…"
            className="flex-1 border border-gray-200 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            onClick={e => { e.stopPropagation(); send() }}
            disabled={sending || !text.trim()}
            className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg font-medium bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex-shrink-0"
          >
            <Send className="w-3 h-3" />
            {sending ? '…' : 'Send'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── FindingRow ────────────────────────────────────────────────────────────────

function PriorityBadge({ priority }: { priority: string }) {
  const cls = PRIORITY_COLORS[priority] || PRIORITY_COLORS['Standard']
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${cls}`}>
      {priority}
    </span>
  )
}

/** Derive a human evidence-quality label from a finding's confidence + evidence. */
function evidenceQuality(finding: Finding): { label: string; cls: string; tip: string } {
  const ev = (finding.evidence || {}) as Record<string, unknown>
  if (ev.expansion_complete === false) {
    return {
      label: 'Expansion incomplete',
      cls: 'bg-orange-100 text-orange-700',
      tip: 'Some referenced objects could not be fully expanded — validate against the effective object definitions before acting.',
    }
  }
  if (finding.confidence === 'High') {
    return { label: 'High confidence', cls: 'bg-emerald-100 text-emerald-700',
      tip: 'Strong evidence (e.g. complete object expansion and/or hit-count data) — minimal ambiguity.' }
  }
  if (finding.confidence === 'Low') {
    return { label: 'Low confidence', cls: 'bg-gray-100 text-gray-600',
      tip: 'Limited evidence — often missing hit-count / usage data. Treat as indicative and confirm.' }
  }
  return { label: 'Reduced confidence', cls: 'bg-amber-100 text-amber-700',
    tip: 'Moderate evidence; some data gaps may reduce accuracy.' }
}

/** Lazy-loaded per-vendor remediation guidance (mounts only when a row is expanded). */
function VendorRemediation({ finding }: { finding: Finding }) {
  const [rem, setRem] = useState<Remediation | null>(null)
  useEffect(() => {
    let cancelled = false
    getRemediation(finding.finding_type, finding.vendor || undefined)
      .then(r => { if (!cancelled) setRem(r) })
      .catch(() => { if (!cancelled) setRem(null) })
    return () => { cancelled = true }
  }, [finding.finding_type, finding.vendor])
  if (!rem) return null
  return (
    <div className="border-t border-gray-100 pt-4">
      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-1.5">
        Vendor remediation — {rem.vendor}{!rem.vendor_specific && ' (generic)'}
      </h4>
      <div className="bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
        <p className="text-[11px] font-semibold text-slate-500 mb-1">{rem.category_label}</p>
        <p className="text-sm text-slate-700 leading-relaxed">{rem.guidance}</p>
        <p className="text-[11px] text-slate-400 mt-2">{rem.read_only_note}</p>
      </div>
    </div>
  )
}

function EvidenceBadge({ finding }: { finding: Finding }) {
  const q = evidenceQuality(finding)
  return (
    <span title={q.tip} className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold cursor-help ${q.cls}`}>
      {q.label}
    </span>
  )
}

function FindingRow({ finding, onUpdate, selected, onSelect }: {
  finding: Finding; onUpdate: () => void
  selected: boolean; onSelect: (id: string, checked: boolean) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [comment, setComment] = useState(finding.engineer_comment || '')
  const [status, setStatus] = useState(finding.status)
  const [priority, setPriority] = useState<typeof PRIORITIES[number]>((finding.priority as typeof PRIORITIES[number]) || 'Standard')
  const [assignedTo, setAssignedTo] = useState(finding.assigned_to || '')
  const [dueDate, setDueDate] = useState(finding.due_date || '')
  // Risk acceptance
  const [showRiskAccept, setShowRiskAccept] = useState(false)
  const [raReason, setRaReason] = useState(finding.risk_acceptance?.reason || '')
  const [raExpiry, setRaExpiry] = useState(finding.risk_acceptance?.expiry || '')
  const [raRef, setRaRef] = useState(finding.risk_acceptance?.ref || '')
  const [raBy, setRaBy] = useState(finding.risk_acceptance?.accepted_by || '')
  const [saving, setSaving] = useState(false)
  const [showEvidence, setShowEvidence] = useState(false)

  const dirty = (
    status !== finding.status ||
    comment !== (finding.engineer_comment || '') ||
    priority !== (finding.priority || 'Standard') ||
    assignedTo !== (finding.assigned_to || '') ||
    dueDate !== (finding.due_date || '')
  )

  const save = async () => {
    setSaving(true)
    try {
      const payload: Record<string, string | undefined> = {
        status, engineer_comment: comment, priority,
      }
      if (assignedTo !== undefined) payload.assigned_to = assignedTo
      if (dueDate !== undefined) payload.due_date = dueDate
      if (showRiskAccept) {
        payload.risk_acceptance_reason = raReason
        payload.risk_acceptance_expiry = raExpiry
        payload.risk_acceptance_ref = raRef
        payload.risk_accepted_by = raBy
      }
      await updateFinding(finding.id, payload)
      onUpdate()
    } finally {
      setSaving(false)
    }
  }

  const sevBg: Record<string, string> = {
    Critical: 'border-l-red-900', High: 'border-l-red-600', Medium: 'border-l-orange-500',
    Low: 'border-l-amber-500', Informational: 'border-l-slate-300',
  }

  const hasRules = (finding.affected_rules_data?.length ?? 0) > 0

  return (
    <>
      <tr
        className={`border-l-4 ${sevBg[finding.severity] || 'border-l-gray-200'} hover:bg-ink-50 cursor-pointer transition-colors ${selected ? 'bg-brand-50' : ''}`}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-2 py-3 w-8" onClick={e => { e.stopPropagation(); onSelect(finding.id, !selected) }}>
          {selected
            ? <CheckSquare className="w-4 h-4 text-brand-600" />
            : <Square className="w-4 h-4 text-gray-300 hover:text-gray-500" />}
        </td>
        <td className="px-4 py-3"><SeverityBadge severity={finding.severity} size="sm" /></td>
        <td className="px-4 py-3 text-xs text-gray-500">
          <div className="flex flex-col gap-1 items-start">
            <EvidenceBadge finding={finding} />
            <PriorityBadge priority={finding.priority || 'Standard'} />
          </div>
        </td>
        <td className="px-4 py-3 text-xs text-gray-600 whitespace-nowrap">
          <span className="flex items-center gap-1">
            {FINDING_ICONS[finding.finding_type]}
            {FINDING_TYPES[finding.finding_type] || finding.finding_type}
          </span>
        </td>
        <td className="px-4 py-3 text-sm font-medium text-gray-900 max-w-[280px]">
          <div className="line-clamp-2">{finding.title}</div>
          {finding.assigned_to && (
            <div className="text-[10px] text-gray-400 mt-0.5 flex items-center gap-1">
              <User className="w-2.5 h-2.5" />{finding.assigned_to}
            </div>
          )}
          {finding.due_date && (
            <div className="text-[10px] text-gray-400 flex items-center gap-1">
              <Clock className="w-2.5 h-2.5" />Due {finding.due_date}
            </div>
          )}
        </td>
        <td className="px-4 py-3"><StatusBadge status={finding.status} /></td>
        <td className="px-4 py-3 text-gray-400 text-xs max-w-[140px] truncate">
          {finding.engineer_comment || '—'}
        </td>
        <td className="px-4 py-3 text-gray-300 text-xs">
          <div className="flex items-center gap-1">
            {hasRules && (
              <span className="text-xs text-info-500 font-medium">
                {finding.affected_rules_data!.length} rule{finding.affected_rules_data!.length !== 1 ? 's' : ''}
              </span>
            )}
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </td>
      </tr>

      {expanded && (
        <DetailDrawer
          open
          onClose={() => setExpanded(false)}
          width="xl"
          title={finding.title}
          subtitle={FINDING_TYPES[finding.finding_type] || finding.finding_type}
          badges={<><SeverityBadge severity={finding.severity} size="sm" /><StatusBadge status={finding.status} /><ConfidenceBadge confidence={finding.confidence || 'Medium'} /></>}
        >
          <div className="space-y-5">

              {/* Description */}
              <div>
                <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-1.5">Description</h4>
                <p className="text-sm text-gray-700 leading-relaxed">{finding.description}</p>
              </div>

              {/* Affected Rules Panel */}
              {hasRules && (
                <div className="pt-1 border-t border-gray-100">
                  <AffectedRulesPanel finding={finding} />
                </div>
              )}

              {/* Recommendation */}
              {finding.recommendation && (
                <div className="border-t border-gray-100 pt-4">
                  <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-1.5">
                    Recommendation
                  </h4>
                  <div className="bg-blue-50 border-l-4 border-blue-500 rounded-r-lg px-4 py-3 flex gap-2">
                    <AlertTriangle className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-blue-800 leading-relaxed">{finding.recommendation}</p>
                      <p className="text-xs text-blue-500 mt-1 font-medium">
                        ⚠️ Engineer validation and formal change approval required before any action.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Per-vendor remediation guidance (review-only) */}
              <VendorRemediation finding={finding} />

              {/* Evidence toggle */}
              <div className="border-t border-gray-100 pt-3">
                <button
                  onClick={e => { e.stopPropagation(); setShowEvidence(!showEvidence) }}
                  className="text-xs text-gray-400 hover:text-gray-600 font-medium flex items-center gap-1 transition-colors"
                >
                  {showEvidence ? '▾' : '▸'} Raw Evidence
                </button>
                {showEvidence && finding.evidence && Object.keys(finding.evidence).length > 0 && (
                  <EvidenceBox evidence={finding.evidence} />
                )}
              </div>

              {/* Workflow fields */}
              <div className="border-t border-gray-100 pt-4">
                <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-3">Review & Assignment</h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
                  <div>
                    <label className="block text-xs font-bold text-gray-500 uppercase tracking-wide mb-1">Status</label>
                    <select
                      value={status}
                      onChange={e => setStatus(e.target.value as typeof status)}
                      onClick={e => e.stopPropagation()}
                      className="w-full border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-gray-500 uppercase tracking-wide mb-1">Priority</label>
                    <select
                      value={priority}
                      onChange={e => setPriority(e.target.value as typeof PRIORITIES[number])}
                      onClick={e => e.stopPropagation()}
                      className="w-full border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-gray-500 uppercase tracking-wide mb-1">
                      <User className="w-3 h-3 inline mr-1" />Assigned To
                    </label>
                    <input
                      value={assignedTo}
                      onChange={e => setAssignedTo(e.target.value)}
                      onClick={e => e.stopPropagation()}
                      className="w-full border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="engineer@company.com"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-gray-500 uppercase tracking-wide mb-1">
                      <Clock className="w-3 h-3 inline mr-1" />Due Date
                    </label>
                    <input
                      type="date"
                      value={dueDate}
                      onChange={e => setDueDate(e.target.value)}
                      onClick={e => e.stopPropagation()}
                      className="w-full border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wide mb-1">
                    <MessageSquare className="w-3 h-3 inline mr-1" />Engineer Comment
                  </label>
                  <input
                    value={comment}
                    onChange={e => setComment(e.target.value)}
                    onClick={e => e.stopPropagation()}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Add a note or justification…"
                  />
                </div>
              </div>

              {/* Risk Acceptance */}
              {(status === 'Accepted Risk' || showRiskAccept || finding.risk_acceptance?.reason) && (
                <div className="border border-amber-200 rounded-lg bg-amber-50 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-bold text-amber-700 uppercase tracking-wide flex items-center gap-1">
                      <Shield className="w-3.5 h-3.5" /> Risk Acceptance Documentation
                    </h4>
                    {!showRiskAccept && !finding.risk_acceptance?.reason && (
                      <button onClick={e => { e.stopPropagation(); setShowRiskAccept(true) }}
                        className="text-xs text-amber-600 hover:text-amber-800">Add details →</button>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] font-bold text-amber-600 uppercase">Accepted By</label>
                      <input value={raBy} onChange={e => setRaBy(e.target.value)} onClick={e => e.stopPropagation()}
                        className="w-full border border-amber-200 rounded px-2 py-1 text-xs mt-0.5 bg-white"
                        placeholder="Name / role" />
                    </div>
                    <div>
                      <label className="text-[10px] font-bold text-amber-600 uppercase">Approval Reference</label>
                      <input value={raRef} onChange={e => setRaRef(e.target.value)} onClick={e => e.stopPropagation()}
                        className="w-full border border-amber-200 rounded px-2 py-1 text-xs mt-0.5 bg-white"
                        placeholder="Ticket / change ref" />
                    </div>
                    <div>
                      <label className="text-[10px] font-bold text-amber-600 uppercase">Expiry Date</label>
                      <input type="date" value={raExpiry} onChange={e => setRaExpiry(e.target.value)} onClick={e => e.stopPropagation()}
                        className="w-full border border-amber-200 rounded px-2 py-1 text-xs mt-0.5 bg-white" />
                    </div>
                    <div>
                      <label className="text-[10px] font-bold text-amber-600 uppercase">Business Justification</label>
                      <input value={raReason} onChange={e => setRaReason(e.target.value)} onClick={e => e.stopPropagation()}
                        className="w-full border border-amber-200 rounded px-2 py-1 text-xs mt-0.5 bg-white"
                        placeholder="Business reason for accepting this risk" />
                    </div>
                  </div>
                </div>
              )}

              <div className="flex items-center gap-3">
                <button
                  onClick={e => { e.stopPropagation(); save() }}
                  disabled={saving || !dirty}
                  className={`flex items-center gap-1.5 text-sm px-4 py-1.5 rounded-lg font-medium transition-colors
                    ${dirty ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-gray-100 text-gray-400 cursor-not-allowed'}`}
                >
                  <Check className="w-3.5 h-3.5" />
                  {saving ? 'Saving…' : 'Save'}
                </button>
                {!dirty && <span className="text-xs text-gray-400">No changes</span>}
                {status === 'Accepted Risk' && !showRiskAccept && !finding.risk_acceptance?.reason && (
                  <button onClick={e => { e.stopPropagation(); setShowRiskAccept(true) }}
                    className="text-xs text-amber-600 hover:text-amber-800 flex items-center gap-1">
                    <Shield className="w-3 h-3" /> Document risk acceptance
                  </button>
                )}
              </div>

              {/* Comment Thread */}
              <div className="border-t border-gray-100 pt-4">
                <CommentThread findingId={finding.id} />
              </div>

          </div>
        </DetailDrawer>
      )}
    </>
  )
}

// ── Findings Page ─────────────────────────────────────────────────────────────

export function Findings() {
  const [searchParams, setSearchParams] = useSearchParams()
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const { user } = useAuth()
  const customerId = params.customerId || searchParams.get('customer_id') || activeCustomer?.id || ''

  const [findings, setFindings] = useState<Finding[]>([])
  const [total, setTotal] = useState(0)
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({})
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkStatus, setBulkStatus] = useState('')
  const [bulkPriority, setBulkPriority] = useState('')
  const [bulkAssignee, setBulkAssignee] = useState('')
  const [bulkSaving, setBulkSaving] = useState(false)
  const [error, setError] = useState('')
  const [actionError, setActionError] = useState('')

  const toggleSelect = (id: string, checked: boolean) => {
    setSelected(prev => { const s = new Set(prev); checked ? s.add(id) : s.delete(id); return s })
  }
  const toggleAll = () => {
    if (selected.size === findings.length) setSelected(new Set())
    else setSelected(new Set(findings.map(f => f.id)))
  }
  const bulkAssigneeTrim = bulkAssignee.trim()
  const hasBulkChange = !!(bulkStatus || bulkPriority || bulkAssigneeTrim)
  const applyBulk = async () => {
    if (!hasBulkChange || selected.size === 0) return
    setBulkSaving(true)
    setActionError('')
    try {
      const data: { status?: string; priority?: string; assigned_to?: string } = {}
      if (bulkStatus) data.status = bulkStatus
      if (bulkPriority) data.priority = bulkPriority
      if (bulkAssigneeTrim) data.assigned_to = bulkAssigneeTrim
      await bulkUpdateFindings(Array.from(selected), data)
      setSelected(new Set()); setBulkStatus(''); setBulkPriority(''); setBulkAssignee(''); load()
    } catch (e) {
      setActionError(friendlyErrorMessage(e, 'Selected findings could not be updated. Please try again.'))
    } finally { setBulkSaving(false) }
  }

  const severity = searchParams.get('severity') || ''
  const findingType = searchParams.get('finding_type') || ''
  const status = searchParams.get('status') || ''
  const policyId = searchParams.get('policy_id') || ''
  const priority = searchParams.get('priority') || ''
  const assignedTo = searchParams.get('assigned_to') || ''
  const search = searchParams.get('search') || ''

  const load = useCallback(() => {
    setLoading(true)
    setError('')
    const p: Record<string, string | number> = { page, page_size: 50 }
    if (customerId) p.customer_id = customerId
    if (policyId) p.policy_id = policyId
    if (severity) p.severity = severity
    if (findingType) p.finding_type = findingType
    if (status) p.status = status
    if (priority) p.priority = priority
    if (assignedTo) p.assigned_to = assignedTo
    if (search) p.search = search
    getFindings(p)
      .then(r => { setFindings(r.findings); setTotal(r.total); setSeverityCounts(r.severity_counts || {}) })
      .catch(e => {
        setFindings([])
        setTotal(0)
        setSeverityCounts({})
        setError(friendlyErrorMessage(e, 'Findings could not be loaded. Please refresh and try again.'))
      })
      .finally(() => setLoading(false))
  }, [page, customerId, policyId, severity, findingType, status, priority, assignedTo, search])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    getPolicies(pp).then(data => setPolicies(Array.isArray(data) ? data : [])).catch(() => setPolicies([]))
  }, [customerId])

  const setFilter = (key: string, val: string) => {
    const p = new URLSearchParams(searchParams)
    if (val) p.set(key, val); else p.delete(key)
    setSearchParams(p)
    setPage(1)
  }

  const applyPreset = (preset: typeof PRESETS[0]) => {
    const p = new URLSearchParams()
    if (customerId) p.set('customer_id', customerId)
    Object.entries(preset.params).forEach(([k, v]) => p.set(k, v))
    setSearchParams(p)
    setPage(1)
  }

  const clearFilters = () => {
    const p = new URLSearchParams()
    if (customerId) p.set('customer_id', customerId)
    setSearchParams(p); setPage(1)
  }

  const hasFilters = !!(severity || findingType || status || policyId || priority || assignedTo || search)
  const mineActive = !!(assignedTo && user?.email && assignedTo === user.email)
  const toggleMine = () => setFilter('assigned_to', mineActive ? '' : (user?.email || ''))

  // Build export — fetch with auth header then trigger blob download
  const [exporting, setExporting] = useState(false)
  const handleExportCsv = async () => {
    setExporting(true)
    setActionError('')
    try {
      const params: Record<string, string> = {}
      if (customerId) params.customer_id = customerId
      if (policyId) params.policy_id = policyId
      if (severity) params.severity = severity
      if (findingType) params.finding_type = findingType
      if (status) params.status = status
      if (priority) params.priority = priority
      if (assignedTo) params.assigned_to = assignedTo
      if (search) params.search = search
      const url = getFindingsExportUrl(params)
      const res = await fetch(url, { credentials: 'include' })
      if (!res.ok) throw new Error(await fetchFailureMessage(res, 'Findings export could not be prepared. Please try again.'))
      const blob = await res.blob()
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = 'findings.csv'
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Findings export could not be prepared. Please try again.')
    } finally {
      setExporting(false)
    }
  }

  const pageCount = Math.ceil(total / 50)


  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-subtitle">
            {total} finding{total !== 1 ? 's' : ''} · Click a row to review and update status
          </p>
        </div>
        <button
          onClick={handleExportCsv}
          disabled={exporting}
          className="btn-secondary"
        >
          <Download className="w-4 h-4" />
          {exporting ? 'Exporting…' : 'Export CSV'}
        </button>
      </div>
    <div className="page-body">
      {actionError && (
        <ErrorState title="Action could not be completed" message={actionError} className="mb-4" />
      )}
      {/* Severity summary bar — click a card to filter by that severity */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mb-4">
        {(['Critical', 'High', 'Medium', 'Low', 'Informational'] as const).map(sev => {
          const count = severityCounts[sev] || 0
          const active = severity === sev
          return (
            <button
              key={sev}
              onClick={() => setFilter('severity', active ? '' : sev)}
              className={`flex flex-col items-start rounded-xl border px-3 py-2.5 text-left transition-all
                ${active
                  ? SEVERITY_COLORS[sev] + ' shadow-sm ring-2 ring-offset-1 ring-blue-400'
                  : 'bg-white border-gray-200 hover:border-blue-300 hover:shadow-sm'}`}
            >
              <span className={`text-2xl font-bold leading-none ${active ? '' : 'text-gray-900'}`}>{count}</span>
              <span className={`mt-1 text-xs font-semibold ${active ? '' : 'text-gray-500'}`}>{sev}</span>
            </button>
          )
        })}
      </div>

      {/* Quick preset chips */}
      <div className="flex flex-wrap gap-2 mb-3">
        {PRESETS.map(preset => {
          const isActive = Object.entries(preset.params).every(([k, v]) => searchParams.get(k) === v)
          return (
            <button
              key={preset.label}
              onClick={() => isActive ? clearFilters() : applyPreset(preset)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border transition-all
                ${isActive
                  ? 'bg-blue-600 border-blue-600 text-white shadow-sm'
                  : 'bg-white border-gray-200 text-gray-600 hover:border-blue-300 hover:text-blue-700'}`}
            >
              {preset.label}
              {isActive && <X className="w-3 h-3 ml-0.5" />}
            </button>
          )
        })}
        {user?.email && (
          <button
            onClick={toggleMine}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border transition-all
              ${mineActive
                ? 'bg-blue-600 border-blue-600 text-white shadow-sm'
                : 'bg-white border-gray-200 text-gray-600 hover:border-blue-300 hover:text-blue-700'}`}
          >
            <User className="w-3 h-3" /> Assigned to me
            {mineActive && <X className="w-3 h-3 ml-0.5" />}
          </button>
        )}
      </div>

      {/* Detailed filters */}
      <div className="filter-bar mb-5">
        <Filter className="w-4 h-4 text-gray-400 mt-2 flex-shrink-0" />

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            value={search}
            onChange={e => setFilter('search', e.target.value)}
            className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm w-64 bg-gray-50 focus:bg-white"
            placeholder="Search findings, evidence, recommendations..."
          />
        </div>

        <select
          value={policyId}
          onChange={e => setFilter('policy_id', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white"
        >
          <option value="">All Policies</option>
          {policies.map(p => (
            <option key={p.id} value={p.id}>
              {p.firewall_name}{!customerId ? ` (${p.customer_name})` : ` · ${p.vendor}`}
            </option>
          ))}
        </select>

        {(['Critical', 'High', 'Medium', 'Low', 'Informational'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilter('severity', severity === sev ? '' : sev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all
              ${severity === sev
                ? SEVERITY_COLORS[sev]
                : 'border-gray-200 text-gray-500 hover:bg-gray-50'}`}
          >
            {sev}
          </button>
        ))}

        <select
          value={findingType}
          onChange={e => setFilter('finding_type', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white"
        >
          <option value="">All Types</option>
          {Object.entries(FINDING_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>

        <select
          value={status}
          onChange={e => setFilter('status', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white"
        >
          <option value="">All Statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>

        <select
          value={priority}
          onChange={e => setFilter('priority', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white"
        >
          <option value="">All Priorities</option>
          {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
        </select>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="text-xs text-red-500 hover:text-red-700 ml-auto flex items-center gap-1"
          >
            <X className="w-3 h-3" /> Clear filters
          </button>
        )}
      </div>

      {error ? (
        <ErrorState title="Findings unavailable" message={error} />
      ) : loading ? (
        <LoadingState label="Loading findings..." />
      ) : findings.length === 0 ? (
        <EmptyState
          icon={<AlertTriangle className="w-6 h-6" />}
          title={hasFilters ? 'No findings match the selected filters' : 'No findings available yet'}
          description={hasFilters
            ? 'Adjust the filters or clear them to review the full findings list.'
            : 'Run analysis on an uploaded or synced policy to generate cleanup findings.'}
          action={hasFilters ? (
            <button onClick={clearFilters} className="btn-secondary">Clear filters</button>
          ) : null}
        />
      ) : (
        <div className="rounded-lg border border-ink-200/80 bg-white shadow-card overflow-auto max-h-[70vh]">
          {/* Bulk action bar */}
          {selected.size > 0 && (
            <div className="flex items-center gap-3 px-4 py-2.5 bg-blue-50 border-b border-blue-200">
              <span className="text-sm font-semibold text-blue-700">{selected.size} selected</span>
              <select
                value={bulkStatus}
                onChange={e => setBulkStatus(e.target.value)}
                className="border border-blue-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Set status…</option>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select
                value={bulkPriority}
                onChange={e => setBulkPriority(e.target.value)}
                className="border border-blue-300 rounded-lg px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Set priority…</option>
                {PRIORITIES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <input
                value={bulkAssignee}
                onChange={e => setBulkAssignee(e.target.value)}
                placeholder="Assign to…"
                className="border border-blue-300 rounded-lg px-3 py-1.5 text-sm bg-white w-36 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={applyBulk}
                disabled={!hasBulkChange || bulkSaving}
                className="flex items-center gap-1.5 text-sm px-4 py-1.5 rounded-lg font-medium bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <Check className="w-3.5 h-3.5" />
                {bulkSaving ? 'Saving…' : 'Apply'}
              </button>
              <button onClick={() => setSelected(new Set())} className="text-xs text-blue-500 hover:text-blue-700 ml-1">
                Clear
              </button>
            </div>
          )}

          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-2 py-3 w-8">
                  <button onClick={toggleAll} className="flex items-center">
                    {selected.size === findings.length && findings.length > 0
                      ? <CheckSquare className="w-4 h-4 text-brand-600" />
                      : <Square className="w-4 h-4 text-gray-300" />}
                  </button>
                </th>
                {['Severity', 'Conf.', 'Type', 'Finding', 'Status', 'Comment', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {findings.map(f => (
                <FindingRow key={f.id} finding={f} onUpdate={load}
                  selected={selected.has(f.id)} onSelect={toggleSelect} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination — outside the scroll container so it is always reachable */}
      {!loading && !error && pageCount > 1 && (
        <div className="mt-3 flex items-center justify-between rounded-lg border border-ink-200/80 bg-white px-4 py-3 text-sm shadow-card">
          <span className="text-gray-500">Page {page} of {pageCount} · {total} total</span>
          <div className="flex gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="btn-secondary py-1 px-3 text-xs">← Prev</button>
            <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} disabled={page === pageCount}
              className="btn-secondary py-1 px-3 text-xs">Next →</button>
          </div>
        </div>
      )}
    </div>{/* end page-body */}
    </div>
  )
}
