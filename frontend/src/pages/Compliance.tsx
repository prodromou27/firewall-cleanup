/**
 * Compliance Framework Dashboard
 * ================================
 * Runs PCI-DSS v4.0, CIS Controls v8, NIST CSF 2.0, and ISO 27001:2022
 * compliance checks against an analysed policy.
 *
 * Features:
 *  - Framework selector (tabs)
 *  - Score gauge + grade badge
 *  - Per-check accordion with pass/warn/fail indicators
 *  - Cross-framework comparison summary card
 *  - Policy selector (all policies or customer-scoped)
 *
 * SAFETY: Read-only. All recommendations explicitly state engineer validation required.
 */
import { useEffect, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  CheckCircle2, XCircle, AlertTriangle, Info, ChevronDown, ChevronUp,
  RefreshCw, Shield, Award, BarChart3, FileText,
} from 'lucide-react'
import { clsx } from 'clsx'
import { getPolicies, getCompliance, getComplianceAll, getComplianceFrameworks } from '../api/client'
import type { Policy } from '../types'

// ── Types ─────────────────────────────────────────────────────────────────────

interface ComplianceCheck {
  check_id:       string
  control_ref:    string
  category:       string
  title:          string
  status:         'pass' | 'warn' | 'fail' | 'info' | 'na'
  severity:       string
  detail:         string
  recommendation: string
  evidence:       Record<string, unknown>
}

interface ComplianceResult {
  framework:      string
  framework_name: string
  policy_id:      string
  firewall_name:  string
  vendor:         string
  score:          number
  grade:          'A' | 'B' | 'C' | 'D' | 'F'
  summary:        { total: number; passed: number; failed: number; warned: number }
  checks:         ComplianceCheck[]
}

interface FrameworkSummary {
  framework:      string
  framework_name: string
  score:          number | null
  grade:          string | null
  summary?:       { total: number; passed: number; failed: number; warned: number }
  error?:         string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const FRAMEWORK_META: Record<string, { color: string; bg: string; description: string }> = {
  'pci-dss':  { color: 'text-red-700',    bg: 'bg-red-50 border-red-200',       description: 'Payment Card Industry Data Security Standard v4.0' },
  'cis':      { color: 'text-blue-700',   bg: 'bg-blue-50 border-blue-200',     description: 'Center for Internet Security Controls v8' },
  'nist':     { color: 'text-purple-700', bg: 'bg-purple-50 border-purple-200', description: 'NIST Cybersecurity Framework 2.0' },
  'iso27001': { color: 'text-green-700',  bg: 'bg-green-50 border-green-200',   description: 'ISO/IEC 27001:2022 Information Security' },
  'gdpr':     { color: 'text-teal-700',   bg: 'bg-teal-50 border-teal-200',     description: 'GDPR Article 32 — Security of Processing (Regulation (EU) 2016/679)' },
}

const STATUS_CFG = {
  pass: { icon: CheckCircle2, cls: 'text-green-600',  bg: 'bg-green-50',   badge: 'bg-green-100 text-green-700', label: 'Pass' },
  warn: { icon: AlertTriangle,cls: 'text-amber-600',  bg: 'bg-amber-50',   badge: 'bg-amber-100 text-amber-700', label: 'Warning' },
  fail: { icon: XCircle,      cls: 'text-red-600',    bg: 'bg-red-50',     badge: 'bg-red-100 text-red-700',     label: 'Fail' },
  info: { icon: Info,         cls: 'text-blue-500',   bg: 'bg-blue-50',    badge: 'bg-blue-100 text-blue-700',   label: 'Info' },
  na:   { icon: Info,         cls: 'text-gray-400',   bg: 'bg-gray-50',    badge: 'bg-gray-100 text-gray-500',   label: 'N/A' },
}

const GRADE_COLORS: Record<string, string> = {
  A: 'text-green-700 bg-green-100 border-green-300',
  B: 'text-blue-700 bg-blue-100 border-blue-300',
  C: 'text-amber-700 bg-amber-100 border-amber-300',
  D: 'text-orange-700 bg-orange-100 border-orange-300',
  F: 'text-red-700 bg-red-100 border-red-300',
}

function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  const circumference = 2 * Math.PI * 40
  const offset = circumference - (score / 100) * circumference
  const color = score >= 90 ? '#16a34a' : score >= 75 ? '#2563eb' : score >= 60 ? '#d97706' : score >= 50 ? '#ea580c' : '#dc2626'

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-28 h-28">
        <svg className="w-28 h-28 -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#e5e7eb" strokeWidth="10" />
          <circle
            cx="50" cy="50" r="40" fill="none"
            stroke={color} strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-gray-800">{score}</span>
          <span className="text-xs text-gray-400">/ 100</span>
        </div>
      </div>
      <span className={clsx(
        'mt-2 text-2xl font-black px-3 py-0.5 rounded-lg border-2',
        GRADE_COLORS[grade] || GRADE_COLORS['F']
      )}>
        {grade}
      </span>
    </div>
  )
}

function CheckRow({ check }: { check: ComplianceCheck }) {
  const [open, setOpen] = useState(false)
  const cfg = STATUS_CFG[check.status] || STATUS_CFG.info
  const Icon = cfg.icon

  return (
    <div className={clsx('border rounded-lg overflow-hidden', check.status === 'fail' ? 'border-red-200' : check.status === 'warn' ? 'border-amber-200' : 'border-gray-200')}>
      <button
        className={clsx('w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-50 transition-colors', cfg.bg)}
        onClick={() => setOpen(o => !o)}
      >
        <Icon className={clsx('w-4 h-4 flex-shrink-0', cfg.cls)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-gray-400">{check.check_id}</span>
            <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded', cfg.badge)}>{cfg.label}</span>
            {check.severity !== 'Informational' && (
              <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded',
                check.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                check.severity === 'High'     ? 'bg-orange-100 text-orange-700' :
                check.severity === 'Medium'   ? 'bg-yellow-100 text-yellow-700' :
                'bg-gray-100 text-gray-600'
              )}>{check.severity}</span>
            )}
          </div>
          <p className="text-sm font-medium text-gray-800 mt-0.5 truncate">{check.title}</p>
        </div>
        <span className="text-xs text-gray-400 hidden sm:block whitespace-nowrap">{check.category}</span>
        {open ? <ChevronUp className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />}
      </button>

      {open && (
        <div className="px-4 py-3 border-t border-gray-100 bg-white space-y-3">
          <div>
            <p className="text-xs font-semibold text-gray-500 mb-1">Control Reference</p>
            <p className="text-xs font-mono text-blue-600">{check.control_ref}</p>
          </div>
          <div>
            <p className="text-xs font-semibold text-gray-500 mb-1">Finding</p>
            <p className="text-sm text-gray-700">{check.detail}</p>
          </div>
          {check.recommendation && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
              <p className="text-xs font-semibold text-blue-700 mb-1">⚡ Recommendation</p>
              <p className="text-sm text-blue-800">{check.recommendation}</p>
              <p className="text-xs text-blue-600 mt-2 italic">
                ⚠ Engineer validation and formal change approval required before implementing any change.
              </p>
            </div>
          )}
          {Object.keys(check.evidence).length > 0 && (
            <details className="group">
              <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-700">Show evidence data</summary>
              <div className="mt-1 bg-gray-50 rounded p-2 text-xs font-mono text-gray-600 overflow-auto max-h-32">
                {JSON.stringify(check.evidence, null, 2)}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export function Compliance({ embedded }: { embedded?: boolean } = {}) {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''

  const [policies, setPolicies]               = useState<Policy[]>([])
  const [selectedPolicy, setSelectedPolicy]   = useState<string>('')
  const [activeFramework, setActiveFramework] = useState('pci-dss')
  const [result, setResult]                   = useState<ComplianceResult | null>(null)
  const [allResults, setAllResults]           = useState<FrameworkSummary[] | null>(null)
  const [loading, setLoading]                 = useState(false)
  const [frameworks, setFrameworks]           = useState<{ key: string; name: string }[]>([])

  // Load frameworks list
  useEffect(() => {
    getComplianceFrameworks().then(setFrameworks).catch(() => {})
  }, [])

  // Load policies for selector
  useEffect(() => {
    const params: Record<string, string> = { limit: '100' }
    if (customerId) params.customer_id = customerId
    getPolicies(params).then((raw: unknown) => {
      const data: Policy[] = Array.isArray(raw) ? raw : []
      const completed = data.filter((p: Policy) => p.analysis_status === 'completed')
      setPolicies(completed)
      if (completed.length > 0 && !selectedPolicy) {
        setSelectedPolicy(completed[0].id)
      }
    }).catch(() => {})
  }, [customerId])

  const runCheck = useCallback(async (policyId: string, fw: string) => {
    if (!policyId) return
    setLoading(true)
    setResult(null)
    try {
      const r = await getCompliance(policyId, fw)
      setResult(r)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  const runAll = useCallback(async (policyId: string) => {
    if (!policyId) return
    setLoading(true)
    setAllResults(null)
    try {
      const r = await getComplianceAll(policyId)
      setAllResults(r.frameworks)
      // Also load the active framework detail
      if (r.details?.[activeFramework]) {
        setResult(r.details[activeFramework])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [activeFramework])

  useEffect(() => {
    if (selectedPolicy) {
      runAll(selectedPolicy)
    }
  }, [selectedPolicy])

  const handleFrameworkChange = async (fw: string) => {
    setActiveFramework(fw)
    if (selectedPolicy) {
      await runCheck(selectedPolicy, fw)
    }
  }

  const selectedPolicyObj = policies.find(p => p.id === selectedPolicy)

  // Group checks by category
  const groupedChecks = result?.checks.reduce((acc, c) => {
    const cat = c.category || 'General'
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(c)
    return acc
  }, {} as Record<string, ComplianceCheck[]>) ?? {}

  const fwMeta = FRAMEWORK_META[activeFramework] || { color: 'text-gray-700', bg: 'bg-gray-50 border-gray-200', description: '' }

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      {!embedded && <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-600" /> Compliance
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Automated checks against PCI-DSS, CIS, NIST CSF, ISO 27001, and GDPR Article 32
          </p>
        </div>

        {/* Policy selector */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-600 font-medium whitespace-nowrap">Policy:</label>
          <select
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 bg-white focus:ring-2 focus:ring-blue-500 outline-none min-w-[220px]"
            value={selectedPolicy}
            onChange={e => setSelectedPolicy(e.target.value)}
          >
            {policies.length === 0 && <option value="">No analysed policies</option>}
            {policies.map(p => (
              <option key={p.id} value={p.id}>
                {p.firewall_name} — {p.vendor} ({p.rule_count} rules)
              </option>
            ))}
          </select>
          {selectedPolicy && (
            <button
              onClick={() => runAll(selectedPolicy)}
              disabled={loading}
              className="flex items-center gap-1.5 text-sm px-3 py-1.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
              {loading ? 'Running…' : 'Re-run'}
            </button>
          )}
        </div>
      </div>}

      {/* ── Cross-framework summary ── */}
      {allResults && allResults.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {allResults.map(fw => {
            const meta = FRAMEWORK_META[fw.framework] || { color: 'text-gray-700', bg: 'bg-white border-gray-200', description: '' }
            const isActive = fw.framework === activeFramework
            return (
              <button
                key={fw.framework}
                onClick={() => handleFrameworkChange(fw.framework)}
                className={clsx(
                  'card p-4 text-left hover:shadow-md transition-all',
                  isActive ? 'ring-2 ring-blue-500 shadow-md' : '',
                )}
              >
                <div className="flex items-start justify-between mb-2">
                  <span className={clsx('text-xs font-bold uppercase tracking-wide', meta.color)}>
                    {fw.framework.toUpperCase()}
                  </span>
                  {fw.grade ? (
                    <span className={clsx('text-lg font-black px-2 py-0.5 rounded border', GRADE_COLORS[fw.grade] || GRADE_COLORS['F'])}>
                      {fw.grade}
                    </span>
                  ) : (
                    <span className="text-xs text-red-500">Error</span>
                  )}
                </div>
                <div className="text-2xl font-bold text-gray-800 mb-1">
                  {fw.score !== null ? `${fw.score}%` : '—'}
                </div>
                <p className="text-xs text-gray-500 mb-2">{fw.framework_name}</p>
                {fw.summary && (
                  <div className="flex gap-2 text-[10px]">
                    <span className="text-green-600 font-semibold">{fw.summary.passed}✓</span>
                    <span className="text-red-600 font-semibold">{fw.summary.failed}✗</span>
                    <span className="text-amber-600 font-semibold">{fw.summary.warned}⚠</span>
                  </div>
                )}
              </button>
            )
          })}
        </div>
      )}

      {/* ── Framework detail ── */}
      {!selectedPolicy && (
        <div className="card p-16 text-center">
          <Shield className="w-12 h-12 text-gray-200 mx-auto mb-3" />
          <p className="text-gray-500">Select a policy to run compliance checks</p>
        </div>
      )}

      {selectedPolicy && loading && !result && (
        <div className="card p-16 text-center">
          <RefreshCw className="w-8 h-8 text-blue-400 animate-spin mx-auto mb-3" />
          <p className="text-gray-500">Running compliance checks…</p>
        </div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Score + summary bar */}
          <div className="card p-6">
            <div className="flex items-start gap-6 flex-wrap">
              <ScoreGauge score={result.score} grade={result.grade} />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <h2 className="text-lg font-bold text-gray-900">{result.framework_name}</h2>
                  <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', fwMeta.bg, fwMeta.color)}>
                    {fwMeta.description}
                  </span>
                </div>
                <p className="text-sm text-gray-500 mb-4">
                  {result.firewall_name} · {result.vendor}
                  {selectedPolicyObj && ` · ${selectedPolicyObj.rule_count} rules`}
                </p>

                {/* Progress bars */}
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 w-14">Passed</span>
                    <div className="flex-1 bg-gray-100 rounded-full h-2">
                      <div
                        className="h-2 bg-green-500 rounded-full transition-all"
                        style={{ width: `${result.summary.total ? result.summary.passed / result.summary.total * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-xs font-semibold text-green-700 w-8 text-right">{result.summary.passed}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 w-14">Failed</span>
                    <div className="flex-1 bg-gray-100 rounded-full h-2">
                      <div
                        className="h-2 bg-red-500 rounded-full transition-all"
                        style={{ width: `${result.summary.total ? result.summary.failed / result.summary.total * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-xs font-semibold text-red-700 w-8 text-right">{result.summary.failed}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 w-14">Warning</span>
                    <div className="flex-1 bg-gray-100 rounded-full h-2">
                      <div
                        className="h-2 bg-amber-400 rounded-full transition-all"
                        style={{ width: `${result.summary.total ? result.summary.warned / result.summary.total * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-xs font-semibold text-amber-700 w-8 text-right">{result.summary.warned}</span>
                  </div>
                </div>
              </div>

              {/* Quick stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="text-center bg-green-50 rounded-xl p-3">
                  <CheckCircle2 className="w-5 h-5 text-green-600 mx-auto mb-1" />
                  <div className="text-xl font-bold text-green-700">{result.summary.passed}</div>
                  <div className="text-xs text-green-600">Passed</div>
                </div>
                <div className="text-center bg-red-50 rounded-xl p-3">
                  <XCircle className="w-5 h-5 text-red-600 mx-auto mb-1" />
                  <div className="text-xl font-bold text-red-700">{result.summary.failed}</div>
                  <div className="text-xs text-red-600">Failed</div>
                </div>
                <div className="text-center bg-amber-50 rounded-xl p-3">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto mb-1" />
                  <div className="text-xl font-bold text-amber-700">{result.summary.warned}</div>
                  <div className="text-xs text-amber-600">Warnings</div>
                </div>
              </div>
            </div>
          </div>

          {/* Checks grouped by category */}
          {Object.entries(groupedChecks).map(([category, checks]) => (
            <div key={category} className="card overflow-hidden">
              <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-700">{category}</h3>
                <div className="flex gap-2 text-[11px]">
                  <span className="text-green-600 font-bold">{checks.filter(c => c.status === 'pass').length} pass</span>
                  <span className="text-red-600 font-bold">{checks.filter(c => c.status === 'fail').length} fail</span>
                  <span className="text-amber-600 font-bold">{checks.filter(c => c.status === 'warn').length} warn</span>
                </div>
              </div>
              <div className="p-3 space-y-2">
                {checks
                  .sort((a, b) => {
                    const order = { fail: 0, warn: 1, info: 2, pass: 3, na: 4 }
                    return (order[a.status] ?? 4) - (order[b.status] ?? 4)
                  })
                  .map(check => (
                    <CheckRow key={check.check_id} check={check} />
                  ))
                }
              </div>
            </div>
          ))}

          {/* Disclaimer */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-800">
            <p className="font-semibold mb-1">⚠ Important: Read-Only Analysis</p>
            <p>
              These compliance checks are automated observations only. No firewall configuration has been modified.
              All remediation actions require <strong>engineer validation, formal risk assessment,
              and change management approval</strong> before implementation.
              Results should be reviewed by a qualified security engineer in the context of the full environment.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
