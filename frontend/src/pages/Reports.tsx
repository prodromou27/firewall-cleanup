/**
 * PolicyInsight — Custom Report Builder
 * 4-step wizard: Type → Scope & Sections → Categories → Options & Generate
 * Templates stored in localStorage.
 */
import { useEffect, useState, useMemo, useCallback } from 'react'
import { useSearchParams, useParams, Link } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  FileText, Download, ExternalLink, Shield, AlertTriangle,
  FileSpreadsheet, FileJson, Globe, Loader, ChevronRight,
  ChevronLeft, Check, Eye, Settings2, Bookmark, BookOpen,
  BarChart2, Zap, Layers, ClipboardList, TrendingUp, Activity,
  Trash2, Save, RotateCcw, Plus,
} from 'lucide-react'
import { getPolicies, getFindings } from '../api/client'
import type { Policy } from '../types'
import { clsx } from 'clsx'

/* ── Types ────────────────────────────────────────────────────────────────── */

type Step = 'type' | 'scope' | 'categories' | 'generate'
type DetailLevel = 'summary' | 'standard' | 'detailed'

interface Branding {
  companyName: string
  confidentiality: string
  preparedBy: string
  accentColor: string
  reportTitle: string
}

interface ReportConfig {
  reportType: string
  sections: string[]
  findingCategories: string[]
  detailLevel: DetailLevel
  includeRules: boolean
  appendices: string[]
  branding: Branding
  severities: string[]
  statuses: string[]
  findingIds: string[] | null
}

interface Template {
  id: string
  name: string
  config: ReportConfig
  createdAt: string
}

/* ── Constants ────────────────────────────────────────────────────────────── */

const STEPS: { key: Step; label: string }[] = [
  { key: 'type',       label: 'Report Type' },
  { key: 'scope',      label: 'Scope & Sections' },
  { key: 'categories', label: 'Finding Categories' },
  { key: 'generate',   label: 'Options & Export' },
]

const REPORT_TYPES = [
  {
    key: 'executive',
    label: 'Executive Summary',
    icon: TrendingUp,
    desc: 'High-level overview for management — scores, top risks, and observations.',
    color: 'text-blue-600', bg: 'bg-blue-50',
    defaultSections: ['exec_summary', 'findings_summary', 'posture'],
    defaultCats: ['overly_permissive','disabled_rule','zero_hit_rule','shadowed_rule','risky_service'],
    detail: 'summary' as DetailLevel,
  },
  {
    key: 'technical',
    label: 'Technical Findings',
    icon: ClipboardList,
    desc: 'Detailed customer-facing report with full findings, evidence and recommendations.',
    color: 'text-indigo-600', bg: 'bg-indigo-50',
    defaultSections: ['exec_summary','scope','findings_summary','findings_detail'],
    defaultCats: 'all',
    detail: 'standard' as DetailLevel,
  },
  {
    key: 'internal',
    label: 'Internal Engineering',
    icon: Settings2,
    desc: 'Full technical export for engineers — all findings, evidence, and rulebase.',
    color: 'text-gray-600', bg: 'bg-gray-100',
    defaultSections: ['exec_summary','findings_summary','findings_detail'],
    defaultCats: 'all',
    detail: 'detailed' as DetailLevel,
  },
  {
    key: 'cleanup',
    label: 'Cleanup Candidates',
    icon: Layers,
    desc: 'Rules and objects that are candidates for review or removal.',
    color: 'text-amber-600', bg: 'bg-amber-50',
    defaultSections: ['exec_summary','findings_summary','findings_detail'],
    defaultCats: ['disabled_rule','zero_hit_rule','low_usage_rule','duplicate_rule','shadowed_rule','temporary_rule','unused_object','duplicate_object'],
    detail: 'standard' as DetailLevel,
  },
  {
    key: 'posture',
    label: 'Security Posture',
    icon: Activity,
    desc: 'Health score, complexity, posture metrics and risk exposure summary.',
    color: 'text-emerald-600', bg: 'bg-emerald-50',
    defaultSections: ['exec_summary','posture','findings_summary'],
    defaultCats: ['overly_permissive','risky_service','no_logging','vpn_access','nat_complexity'],
    detail: 'summary' as DetailLevel,
  },
  {
    key: 'comparison',
    label: 'Before & After',
    icon: BarChart2,
    desc: 'Compare two policy revisions — added/removed rules, risk delta.',
    color: 'text-purple-600', bg: 'bg-purple-50',
    defaultSections: ['exec_summary','findings_summary','findings_detail'],
    defaultCats: 'all',
    detail: 'standard' as DetailLevel,
  },
  {
    key: 'compliance',
    label: 'Compliance Mapping',
    icon: BookOpen,
    desc: 'Map findings to security control areas with supporting evidence.',
    color: 'text-rose-600', bg: 'bg-rose-50',
    defaultSections: ['exec_summary','scope','findings_summary','findings_detail'],
    defaultCats: ['overly_permissive','no_logging','risky_service','vpn_access'],
    detail: 'standard' as DetailLevel,
  },
]

const SECTION_GROUPS: Array<{ group: string; items: Array<{ key: string; label: string; desc: string; appendix?: boolean }> }> = [
  {
    group: 'General',
    items: [
      { key: 'exec_summary',     label: 'Executive Summary',    desc: 'Score, severity counts, key observations' },
      { key: 'scope',            label: 'Scope & Methodology',  desc: 'Analysis scope, firewall inventory, methodology' },
      { key: 'posture',          label: 'Security Posture',     desc: 'Health, complexity and cleanup readiness scores' },
    ],
  },
  {
    group: 'Findings',
    items: [
      { key: 'findings_summary', label: 'Findings Summary Table', desc: 'Count by severity and category' },
      { key: 'findings_detail',  label: 'Findings Detail',        desc: 'Full per-category finding tables' },
    ],
  },
  {
    group: 'Appendices',
    items: [
      { key: 'appendix_rulebase', label: 'Full Rulebase', desc: 'Complete rule table (max 600 rules in HTML)', appendix: true },
    ],
  },
]

const RULE_CATEGORIES = [
  { key: 'overly_permissive', label: 'Overly Permissive Rules' },
  { key: 'disabled_rule',     label: 'Disabled Rules' },
  { key: 'zero_hit_rule',     label: 'Zero-Hit Rules' },
  { key: 'low_usage_rule',    label: 'Low-Usage Rules' },
  { key: 'duplicate_rule',    label: 'Duplicate Rules' },
  { key: 'shadowed_rule',     label: 'Shadowed Rules' },
  { key: 'risky_service',     label: 'Risky Services' },
  { key: 'no_logging',        label: 'Rules Without Logging' },
  { key: 'temporary_rule',    label: 'Temporary Rules' },
  { key: 'expired_rule',      label: 'Expired Rules' },
  { key: 'no_documentation',  label: 'Undocumented Rules' },
  { key: 'naming_quality',    label: 'Naming Quality' },
  { key: 'nat_complexity',    label: 'NAT Rule Findings' },
  { key: 'vpn_access',        label: 'Broad VPN Access' },
  { key: 'negated_object',    label: 'Negated Object Rules' },
]

const OBJECT_CATEGORIES = [
  { key: 'unused_object',    label: 'Unused Objects' },
  { key: 'duplicate_object', label: 'Duplicate Objects' },
  { key: 'empty_group',      label: 'Empty Groups' },
  { key: 'large_group',      label: 'Large Groups' },
  { key: 'broad_network',    label: 'Broad Network Objects' },
  { key: 'service_range',    label: 'Wide Service Ranges' },
]

const ALL_CATEGORIES = [...RULE_CATEGORIES, ...OBJECT_CATEGORIES].map(c => c.key)

const SEVERITIES = ['High', 'Medium', 'Low', 'Informational']
const STATUSES   = ['New','Review Required','In Review','Confirmed Cleanup Candidate',
                    'Manual Change Required','Change Planned Outside Tool',
                    'Cleanup Completed Outside Tool','False Positive','Accepted Risk','Deferred']

const CONFIDENTIALITY_LABELS = ['Confidential','Internal Use Only','Customer Confidential','Restricted','Draft','Final']

const ACCENT_COLORS = [
  { value: '#1e3a5f', label: 'Navy'    },
  { value: '#1e40af', label: 'Blue'    },
  { value: '#065f46', label: 'Green'   },
  { value: '#6b21a8', label: 'Purple'  },
  { value: '#9f1239', label: 'Red'     },
  { value: '#374151', label: 'Slate'   },
  { value: '#92400e', label: 'Amber'   },
]

const DEFAULT_CONFIG: ReportConfig = {
  reportType:        'technical',
  sections:          ['exec_summary','scope','findings_summary','findings_detail'],
  findingCategories: ALL_CATEGORIES,
  detailLevel:       'standard',
  includeRules:      true,
  appendices:        [],
  branding: {
    companyName:     'PolicyInsight',
    confidentiality: 'Confidential',
    preparedBy:      '',
    accentColor:     '#1e3a5f',
    reportTitle:     '',
  },
  severities: SEVERITIES,
  statuses:   STATUSES,
  findingIds: null,
}

const TEMPLATES_KEY = 'policyinsight_report_templates'

/* ── LocalStorage helpers ─────────────────────────────────────────────────── */
function loadTemplates(): Template[] {
  try { return JSON.parse(localStorage.getItem(TEMPLATES_KEY) || '[]') } catch { return [] }
}
function saveTemplates(ts: Template[]) {
  localStorage.setItem(TEMPLATES_KEY, JSON.stringify(ts))
}

/* ── SEV colours ──────────────────────────────────────────────────────────── */
const SEV_DOT: Record<string, string> = {
  High: 'bg-red-500', Medium: 'bg-amber-400', Low: 'bg-blue-500', Informational: 'bg-gray-400',
}

/* ── Main component ───────────────────────────────────────────────────────── */
export function Reports() {
  const [searchParams] = useSearchParams()
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''

  /* State */
  const [step, setStep]               = useState<Step>('type')
  const [config, setConfig]           = useState<ReportConfig>(DEFAULT_CONFIG)
  const [policies, setPolicies]       = useState<Policy[]>([])
  const [selectedId, setSelectedId]   = useState(searchParams.get('policy_id') || '')
  const [loadingPol, setLoadingPol]   = useState(true)
  const [findings, setFindings]       = useState<{ id: string; finding_type: string; severity: string; title: string; status: string }[]>([])
  const [loadingF, setLoadingF]       = useState(false)
  const [generating, setGenerating]   = useState<string | null>(null)
  const [templates, setTemplates]     = useState<Template[]>(loadTemplates)
  const [showTemplates, setShowTemplates] = useState(false)
  const [templateName, setTemplateName]   = useState('')
  const [savingTemplate, setSavingTemplate] = useState(false)
  const [genCSummary, setGenCSummary] = useState<string | null>(null)

  /* Load policies */
  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    setLoadingPol(true)
    getPolicies(pp)
      .then((raw: unknown) => {
        const list: Policy[] = Array.isArray(raw) ? raw : []
        setPolicies(list)
        if (!selectedId && list.length === 1) setSelectedId(list[0].id)
      })
      .finally(() => setLoadingPol(false))
  }, [customerId])

  /* Load findings when policy changes */
  useEffect(() => {
    if (!selectedId) { setFindings([]); return }
    setLoadingF(true)
    getFindings({ policy_id: selectedId, page_size: 1000 })
      .then((r: unknown) => {
        const list = Array.isArray(r) ? r : ((r as any)?.findings ?? [])
        setFindings(list)
      })
      .finally(() => setLoadingF(false))
  }, [selectedId])

  const policy = policies.find(p => p.id === selectedId)

  /* Finding counts by type in this policy */
  const typeCounts = useMemo(() => {
    const m: Record<string, number> = {}
    findings.forEach(f => { m[f.finding_type] = (m[f.finding_type] || 0) + 1 })
    return m
  }, [findings])

  /* Apply a report type preset */
  const applyType = useCallback((typeKey: string) => {
    const rt = REPORT_TYPES.find(t => t.key === typeKey)
    if (!rt) return
    const cats = rt.defaultCats === 'all' ? ALL_CATEGORIES : rt.defaultCats as string[]
    const appendices = rt.defaultSections.includes('appendix_rulebase') ? ['appendix_rulebase'] : []
    const sections = rt.defaultSections.filter(s => !s.startsWith('appendix_'))
    setConfig(prev => ({
      ...prev,
      reportType: typeKey,
      sections,
      findingCategories: cats,
      detailLevel: rt.detail,
      appendices,
    }))
  }, [])

  /* Helpers */
  const toggleSection = (key: string, isAppendix: boolean) => {
    if (isAppendix) {
      setConfig(prev => ({
        ...prev,
        appendices: prev.appendices.includes(key)
          ? prev.appendices.filter(a => a !== key)
          : [...prev.appendices, key],
      }))
    } else {
      setConfig(prev => ({
        ...prev,
        sections: prev.sections.includes(key)
          ? prev.sections.filter(s => s !== key)
          : [...prev.sections, key],
      }))
    }
  }

  const toggleCat = (key: string) =>
    setConfig(prev => ({
      ...prev,
      findingCategories: prev.findingCategories.includes(key)
        ? prev.findingCategories.filter(c => c !== key)
        : [...prev.findingCategories, key],
    }))

  const selectAllCats = () => setConfig(prev => ({ ...prev, findingCategories: ALL_CATEGORIES }))
  const clearAllCats  = () => setConfig(prev => ({ ...prev, findingCategories: [] }))

  /* Template management */
  const saveTemplate = () => {
    if (!templateName.trim()) return
    const t: Template = {
      id: crypto.randomUUID(),
      name: templateName.trim(),
      config,
      createdAt: new Date().toISOString(),
    }
    const updated = [t, ...templates]
    setTemplates(updated)
    saveTemplates(updated)
    setTemplateName('')
    setSavingTemplate(false)
  }

  const loadTemplate = (t: Template) => {
    setConfig(t.config)
    setShowTemplates(false)
  }

  const deleteTemplate = (id: string) => {
    const updated = templates.filter(t => t.id !== id)
    setTemplates(updated)
    saveTemplates(updated)
  }

  /* Build POST body for the report builder endpoint */
  const buildPayload = () => ({
    report_type:        config.reportType,
    detail_level:       config.detailLevel,
    sections:           config.sections,
    finding_categories: config.findingCategories,
    severities:         config.severities,
    statuses:           config.statuses,
    finding_ids:        config.findingIds,
    include_rules:      config.includeRules,
    appendices:         config.appendices,
    branding: {
      company_name:    config.branding.companyName,
      customer_name:   policy?.customer_name || '',
      confidentiality: config.branding.confidentiality,
      prepared_by:     config.branding.preparedBy,
      accent_color:    config.branding.accentColor,
      report_title:    config.branding.reportTitle || undefined,
    },
  })

  const generateReport = async (format: 'html' | 'excel' | 'csv' | 'json') => {
    if (!selectedId) return
    setGenerating(format)
    try {
      const url = `/api/reports/${selectedId}/build?format=${format}`
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(buildPayload()),
      })
      if (!resp.ok) throw new Error(`${resp.status}`)
      const blob = await resp.blob()
      const cd = resp.headers.get('content-disposition') || ''
      const name = cd.match(/filename="?([^";]+)"?/)?.[1] || `report.${format === 'excel' ? 'xlsx' : format}`
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = blobUrl
      if (format === 'html') { a.target = '_blank'; a.rel = 'noopener' }
      else a.download = name
      document.body.appendChild(a); a.click(); document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(blobUrl), 15_000)
    } catch (e) { console.error('Report generation failed', e) }
    finally { setTimeout(() => setGenerating(null), 400) }
  }

  const downloadCustomerSummary = async (fmt: 'json' | 'excel') => {
    if (!customerId) return
    setGenCSummary(fmt)
    try {
      const url = `/api/reports/customer/${customerId}/summary?format=${fmt}`
      const resp = await fetch(url, { credentials: 'include' })
      if (!resp.ok) throw new Error(`${resp.status}`)
      const blob = await resp.blob()
      const cd = resp.headers.get('content-disposition') || ''
      const fname = cd.match(/filename="?([^";]+)"?/)?.[1] || `summary.${fmt === 'excel' ? 'xlsx' : 'json'}`
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = blobUrl; a.download = fname; a.click()
      URL.revokeObjectURL(blobUrl)
    } catch (e) { console.error(e) }
    finally { setTimeout(() => setGenCSummary(null), 500) }
  }

  const stepIdx = STEPS.findIndex(s => s.key === step)
  const canNext = step !== 'generate'
  const canBack = step !== 'type'

  const next = () => {
    const idx = STEPS.findIndex(s => s.key === step)
    if (idx < STEPS.length - 1) setStep(STEPS[idx + 1].key)
  }
  const back = () => {
    const idx = STEPS.findIndex(s => s.key === step)
    if (idx > 0) setStep(STEPS[idx - 1].key)
  }

  /* ── Render ── */
  return (
    <div>
      {/* Header */}
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Report Builder</h1>
          <p className="page-subtitle">
            Create professional, customisable firewall audit reports — choose type, sections, categories, and branding
          </p>
        </div>
        <div className="flex items-center gap-2">
          {customerId && (
            <>
              <button onClick={() => downloadCustomerSummary('excel')}
                disabled={genCSummary !== null}
                className="btn-secondary text-xs"
                title="Customer-wide summary (all policies)">
                {genCSummary === 'excel' ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />}
                Customer Excel
              </button>
              <button onClick={() => downloadCustomerSummary('json')}
                disabled={genCSummary !== null}
                className="btn-secondary text-xs">
                {genCSummary === 'json' ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <FileJson className="w-3.5 h-3.5 text-purple-600" />}
                Customer JSON
              </button>
            </>
          )}
          <button onClick={() => setShowTemplates(v => !v)} className="btn-secondary text-xs">
            <Bookmark className="w-3.5 h-3.5" /> Templates {templates.length > 0 && `(${templates.length})`}
          </button>
        </div>
      </div>

      <div className="page-body max-w-5xl">

        {/* Templates drawer */}
        {showTemplates && (
          <div className="card mb-5 bg-amber-50 border-amber-200">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-gray-800 flex items-center gap-2">
                <Bookmark className="w-4 h-4 text-amber-600" /> Saved Templates
              </h3>
              <button onClick={() => setShowTemplates(false)} className="btn-ghost btn-sm text-xs">✕ Close</button>
            </div>
            {templates.length === 0 ? (
              <p className="text-sm text-gray-400">No saved templates. Configure a report and save it as a template below.</p>
            ) : (
              <div className="space-y-2">
                {templates.map(t => (
                  <div key={t.id} className="flex items-center gap-3 bg-white rounded-lg border border-amber-100 px-3 py-2">
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-sm text-gray-800 truncate">{t.name}</p>
                      <p className="text-xs text-gray-400">
                        {REPORT_TYPES.find(rt => rt.key === t.config.reportType)?.label} ·{' '}
                        {t.config.findingCategories.length} categories ·{' '}
                        {new Date(t.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <button onClick={() => loadTemplate(t)} className="btn-secondary btn-sm text-xs">Load</button>
                    <button onClick={() => deleteTemplate(t.id)} className="btn-ghost btn-sm text-xs text-red-500 hover:text-red-700">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Step indicator */}
        <div className="card mb-5 p-0 overflow-hidden">
          <div className="flex">
            {STEPS.map((s, i) => {
              const active   = s.key === step
              const complete = i < stepIdx
              return (
                <button
                  key={s.key}
                  onClick={() => setStep(s.key)}
                  className={clsx(
                    'flex-1 py-3.5 px-2 text-center text-xs font-semibold transition-all relative',
                    active   ? 'bg-gray-900 text-white' :
                    complete ? 'bg-gray-50 text-gray-600 hover:bg-gray-100' :
                               'bg-white text-gray-400 hover:bg-gray-50'
                  )}
                >
                  <span className={clsx(
                    'inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-bold mr-1.5',
                    active   ? 'bg-white text-gray-900' :
                    complete ? 'bg-emerald-500 text-white' : 'bg-gray-200 text-gray-500'
                  )}>
                    {complete ? '✓' : i + 1}
                  </span>
                  {s.label}
                  {i < STEPS.length - 1 && (
                    <ChevronRight className="w-3 h-3 absolute right-0 top-1/2 -translate-y-1/2 text-gray-300" />
                  )}
                </button>
              )
            })}
          </div>
        </div>

        {/* ── Step 1: Report Type ── */}
        {step === 'type' && (
          <div>
            <p className="text-xs text-gray-400 mb-4">
              Choose a report type. Each preset auto-selects sections and finding categories — you can customise everything in the next steps.
            </p>
            <div className="grid grid-cols-2 gap-3">
              {REPORT_TYPES.map(rt => {
                const Icon = rt.icon
                const active = config.reportType === rt.key
                return (
                  <button
                    key={rt.key}
                    onClick={() => applyType(rt.key)}
                    className={clsx(
                      'card text-left transition-all group relative',
                      active ? 'ring-2 ring-gray-900 border-gray-900 bg-gray-50' : 'hover:border-gray-300 hover:shadow-sm'
                    )}
                  >
                    {active && <Check className="absolute top-3 right-3 w-4 h-4 text-gray-900" />}
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${rt.bg} flex-shrink-0`}>
                        <Icon className={`w-5 h-5 ${rt.color}`} />
                      </div>
                      <div>
                        <p className="font-semibold text-gray-900 text-sm">{rt.label}</p>
                        <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{rt.desc}</p>
                        <p className="text-[10px] text-gray-300 mt-1.5 font-medium uppercase tracking-wide">
                          Default: {rt.detail} detail
                        </p>
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* ── Step 2: Scope & Sections ── */}
        {step === 'scope' && (
          <div className="space-y-5">
            {/* Policy selector */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Select Firewall / Policy</p>
              <div className="card p-0 overflow-hidden">
                {loadingPol ? (
                  <div className="flex items-center gap-2 text-gray-400 text-sm p-4">
                    <Loader className="w-4 h-4 animate-spin" /> Loading…
                  </div>
                ) : policies.length === 0 ? (
                  <div className="text-center py-10 px-5">
                    <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                    <p className="text-sm text-gray-500 mb-3">No analysed policies found.</p>
                    <Link to={customerId ? `/upload?customer_id=${customerId}` : '/upload'} className="btn-primary text-sm">
                      Upload a Policy
                    </Link>
                  </div>
                ) : (
                  policies.map((p, i) => (
                    <button
                      key={p.id}
                      onClick={() => setSelectedId(p.id)}
                      className={clsx(
                        'w-full flex items-center gap-3 px-4 py-3 text-left transition-colors',
                        i > 0 && 'border-t border-gray-100',
                        selectedId === p.id ? 'bg-gray-50' : 'hover:bg-gray-50/60'
                      )}
                    >
                      <div className={clsx('w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0',
                        selectedId === p.id ? 'bg-gray-900' : 'bg-gray-100')}>
                        <Shield className={clsx('w-3.5 h-3.5', selectedId === p.id ? 'text-white' : 'text-gray-400')} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-gray-900 text-sm truncate">{p.firewall_name}</p>
                        <p className="text-xs text-gray-400">{p.vendor}{p.policy_package ? ` · ${p.policy_package}` : ''}</p>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 text-xs text-gray-400">
                        <span>{p.finding_count} findings</span>
                        {selectedId === p.id && <Check className="w-4 h-4 text-gray-900" />}
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>

            {/* Section checklist */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Report Sections</p>
              <div className="card p-4 space-y-4">
                {SECTION_GROUPS.map(group => (
                  <div key={group.group}>
                    <p className="text-[11px] font-bold text-gray-400 uppercase tracking-widest mb-2">{group.group}</p>
                    <div className="space-y-2">
                      {group.items.map(item => {
                        const isAppendix = !!item.appendix
                        const checked = isAppendix
                          ? config.appendices.includes(item.key)
                          : config.sections.includes(item.key)
                        return (
                          <label key={item.key} className="flex items-start gap-3 cursor-pointer">
                            <div
                              onClick={() => toggleSection(item.key, isAppendix)}
                              className={clsx(
                                'mt-0.5 w-4 h-4 rounded border-2 flex-shrink-0 flex items-center justify-center transition-all cursor-pointer',
                                checked ? 'border-gray-900 bg-gray-900' : 'border-gray-300 bg-white'
                              )}
                            >
                              {checked && <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />}
                            </div>
                            <div onClick={() => toggleSection(item.key, isAppendix)}>
                              <p className="text-sm font-medium text-gray-800">{item.label}</p>
                              <p className="text-xs text-gray-400">{item.desc}</p>
                            </div>
                          </label>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Step 3: Finding Categories ── */}
        {step === 'categories' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-xs text-gray-400">
                {config.findingCategories.length} of {ALL_CATEGORIES.length} categories selected · {findings.length} total findings in policy
              </p>
              <div className="flex gap-2">
                <button onClick={selectAllCats} className="btn-ghost btn-sm text-xs">
                  <Check className="w-3 h-3" /> All
                </button>
                <button onClick={clearAllCats} className="btn-ghost btn-sm text-xs">
                  <RotateCcw className="w-3 h-3" /> None
                </button>
              </div>
            </div>

            {[{ label: 'Rule Findings', cats: RULE_CATEGORIES }, { label: 'Object Findings', cats: OBJECT_CATEGORIES }].map(group => (
              <div key={group.label}>
                <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">{group.label}</p>
                <div className="card p-0 overflow-hidden">
                  {group.cats.map((cat, i) => {
                    const checked = config.findingCategories.includes(cat.key)
                    const count = typeCounts[cat.key] || 0
                    return (
                      <button
                        key={cat.key}
                        onClick={() => toggleCat(cat.key)}
                        className={clsx(
                          'w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors',
                          i > 0 && 'border-t border-gray-50',
                          checked ? 'hover:bg-gray-50/60' : 'opacity-50 hover:opacity-70 bg-gray-50/30'
                        )}
                      >
                        <div className={clsx('w-4 h-4 rounded border-2 flex-shrink-0 flex items-center justify-center',
                          checked ? 'border-gray-900 bg-gray-900' : 'border-gray-300 bg-white')}>
                          {checked && <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />}
                        </div>
                        <span className="flex-1 text-sm font-medium text-gray-800">{cat.label}</span>
                        {count > 0 && (
                          <span className="text-xs font-semibold bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">
                            {count}
                          </span>
                        )}
                        {loadingF && count === 0 && <Loader className="w-3 h-3 text-gray-300 animate-spin" />}
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}

            {/* Severity filter */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Severity Filter</p>
              <div className="card p-4 flex flex-wrap gap-2">
                {SEVERITIES.map(sev => {
                  const active = config.severities.includes(sev)
                  return (
                    <button
                      key={sev}
                      onClick={() => setConfig(prev => ({
                        ...prev,
                        severities: active ? prev.severities.filter(s => s !== sev) : [...prev.severities, sev],
                      }))}
                      className={clsx(
                        'flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all',
                        active ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-200 bg-white text-gray-500 hover:border-gray-300'
                      )}
                    >
                      <span className={clsx('w-1.5 h-1.5 rounded-full', active ? 'bg-white' : SEV_DOT[sev])} />
                      {sev}
                      <span className="opacity-60 font-normal">
                        ({findings.filter(f => f.severity === sev).length})
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── Step 4: Options & Generate ── */}
        {step === 'generate' && (
          <div className="space-y-5">

            {/* Policy check */}
            {!selectedId && (
              <div className="alert-warning">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-500 mt-0.5" />
                <p className="text-xs">No policy selected — go back to Step 2 to choose a firewall policy.</p>
              </div>
            )}

            {/* Detail level */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Detail Level</p>
              <div className="card p-4 flex gap-3">
                {[
                  { key: 'summary',  label: 'Summary',  desc: 'Titles and recommendations only' },
                  { key: 'standard', label: 'Standard', desc: 'Title, description, recommendation' },
                  { key: 'detailed', label: 'Detailed',  desc: 'Full detail including evidence' },
                ].map(dl => (
                  <button
                    key={dl.key}
                    onClick={() => setConfig(prev => ({ ...prev, detailLevel: dl.key as DetailLevel }))}
                    className={clsx(
                      'flex-1 rounded-lg border-2 p-3 text-left transition-all',
                      config.detailLevel === dl.key ? 'border-gray-900 bg-gray-50' : 'border-gray-200 hover:border-gray-300'
                    )}
                  >
                    <p className="text-sm font-semibold text-gray-800">{dl.label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{dl.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Branding */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Branding</p>
              <div className="card p-4 grid grid-cols-2 gap-4">
                <div>
                  <label className="label-sm mb-1.5 block">Company / Firm Name</label>
                  <input
                    value={config.branding.companyName}
                    onChange={e => setConfig(prev => ({ ...prev, branding: { ...prev.branding, companyName: e.target.value } }))}
                    className="input-sm w-full"
                    placeholder="PolicyInsight"
                  />
                </div>
                <div>
                  <label className="label-sm mb-1.5 block">Report Title (optional)</label>
                  <input
                    value={config.branding.reportTitle}
                    onChange={e => setConfig(prev => ({ ...prev, branding: { ...prev.branding, reportTitle: e.target.value } }))}
                    className="input-sm w-full"
                    placeholder="Auto from report type"
                  />
                </div>
                <div>
                  <label className="label-sm mb-1.5 block">Prepared By</label>
                  <input
                    value={config.branding.preparedBy}
                    onChange={e => setConfig(prev => ({ ...prev, branding: { ...prev.branding, preparedBy: e.target.value } }))}
                    className="input-sm w-full"
                    placeholder="Your name or team"
                  />
                </div>
                <div>
                  <label className="label-sm mb-1.5 block">Confidentiality Label</label>
                  <select
                    value={config.branding.confidentiality}
                    onChange={e => setConfig(prev => ({ ...prev, branding: { ...prev.branding, confidentiality: e.target.value } }))}
                    className="input-sm w-full"
                  >
                    {CONFIDENTIALITY_LABELS.map(l => <option key={l} value={l}>{l}</option>)}
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="label-sm mb-1.5 block">Accent Colour</label>
                  <div className="flex items-center gap-2 flex-wrap">
                    {ACCENT_COLORS.map(ac => (
                      <button
                        key={ac.value}
                        onClick={() => setConfig(prev => ({ ...prev, branding: { ...prev.branding, accentColor: ac.value } }))}
                        title={ac.label}
                        className={clsx(
                          'w-7 h-7 rounded-full border-2 transition-all',
                          config.branding.accentColor === ac.value ? 'border-gray-900 scale-110' : 'border-transparent hover:scale-105'
                        )}
                        style={{ background: ac.value }}
                      />
                    ))}
                    <input
                      type="color"
                      value={config.branding.accentColor}
                      onChange={e => setConfig(prev => ({ ...prev, branding: { ...prev.branding, accentColor: e.target.value } }))}
                      className="w-7 h-7 rounded cursor-pointer border border-gray-200"
                      title="Custom colour"
                    />
                    <span className="text-xs text-gray-400 ml-1">Custom</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Include rulebase toggle */}
            <div className="card p-4 flex items-center gap-3">
              <button
                onClick={() => setConfig(prev => ({ ...prev, includeRules: !prev.includeRules }))}
                className={clsx('relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0',
                  config.includeRules ? 'bg-gray-900' : 'bg-gray-200')}>
                <span className={clsx('inline-block h-3.5 w-3.5 rounded-full bg-white shadow transform transition-transform',
                  config.includeRules ? 'translate-x-4' : 'translate-x-0.5')} />
              </button>
              <div>
                <span className="text-sm font-medium text-gray-800">Include full rulebase</span>
                <span className="text-xs text-gray-400 ml-1">(HTML, Excel, JSON)</span>
              </div>
            </div>

            {/* Export scope summary */}
            {selectedId && (
              <div className="card p-4 bg-gray-50 border-gray-200">
                <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Export Scope</p>
                <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-xs text-gray-500">
                  <span>Policy: <strong className="text-gray-900">{policy?.firewall_name || selectedId}</strong></span>
                  <span>Report type: <strong className="text-gray-900">{REPORT_TYPES.find(t => t.key === config.reportType)?.label}</strong></span>
                  <span>Sections: <strong className="text-gray-900">{config.sections.length + config.appendices.length}</strong></span>
                  <span>Finding categories: <strong className="text-gray-900">{config.findingCategories.length}</strong></span>
                  <span>Severities: <strong className="text-gray-900">{config.severities.join(', ')}</strong></span>
                  <span>Detail level: <strong className="text-gray-900 capitalize">{config.detailLevel}</strong></span>
                </div>
              </div>
            )}

            {/* Read-only disclaimer */}
            <div className="alert-readonly">
              <Eye className="w-4 h-4 flex-shrink-0 text-gray-500 mt-0.5" />
              <p className="text-xs leading-relaxed">
                <strong>Read-Only Report.</strong> PolicyInsight does not modify firewall rules or configurations.
                All recommendations require engineer validation and formal change approval before implementation.
              </p>
            </div>

            {/* Export format buttons */}
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Export Format</p>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { fmt: 'html',  label: 'HTML Report',    icon: Globe,         desc: 'Interactive browser view — printable as PDF', color: 'text-blue-600',    bg: 'bg-blue-50',    badge: 'Recommended' },
                  { fmt: 'excel', label: 'Excel Workbook', icon: FileSpreadsheet, desc: 'Multi-sheet workbook with per-category tabs', color: 'text-emerald-600', bg: 'bg-emerald-50', badge: '' },
                  { fmt: 'csv',   label: 'CSV Export',     icon: FileText,      desc: 'Flat findings list for any tool',              color: 'text-gray-600',    bg: 'bg-gray-100',   badge: '' },
                  { fmt: 'json',  label: 'JSON Export',    icon: FileJson,      desc: 'Structured data for integrations',             color: 'text-purple-600',  bg: 'bg-purple-50',  badge: '' },
                ].map(({ fmt, label, icon: Icon, desc, color, bg, badge }) => (
                  <button
                    key={fmt}
                    onClick={() => generateReport(fmt as 'html'|'excel'|'csv'|'json')}
                    disabled={!selectedId || generating !== null}
                    className="card text-left transition-all group hover:border-gray-300 hover:shadow-sm active:scale-[.99] disabled:opacity-40 relative overflow-hidden"
                  >
                    {badge && (
                      <span className="absolute top-3 right-3 text-[10px] font-bold bg-gray-900 text-white px-2 py-0.5 rounded-full">{badge}</span>
                    )}
                    <div className="flex items-start gap-3">
                      <div className={`p-2.5 rounded-lg ${bg} flex-shrink-0`}>
                        {generating === fmt
                          ? <Loader className={`w-5 h-5 ${color} animate-spin`} />
                          : fmt === 'html' ? <ExternalLink className={`w-5 h-5 ${color}`} /> : <Icon className={`w-5 h-5 ${color}`} />
                        }
                      </div>
                      <div className="min-w-0">
                        <p className="font-semibold text-sm text-gray-900">{label}</p>
                        <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
                        <div className={`flex items-center gap-1 mt-2 text-xs font-semibold ${color}`}>
                          {fmt === 'html' ? <><ExternalLink className="w-3 h-3" />Open in browser</> : <><Download className="w-3 h-3" />Download</>}
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Save as template */}
            <div className="card p-4 border-dashed border-gray-300 bg-gray-50">
              {!savingTemplate ? (
                <button onClick={() => setSavingTemplate(true)} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 transition-colors w-full">
                  <Save className="w-4 h-4" />
                  Save current configuration as a reusable template
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <input
                    autoFocus
                    value={templateName}
                    onChange={e => setTemplateName(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') saveTemplate(); if (e.key === 'Escape') setSavingTemplate(false) }}
                    placeholder="Template name…"
                    className="input-sm flex-1"
                  />
                  <button onClick={saveTemplate} disabled={!templateName.trim()} className="btn-primary btn-sm text-xs">
                    <Save className="w-3.5 h-3.5" /> Save
                  </button>
                  <button onClick={() => setSavingTemplate(false)} className="btn-ghost btn-sm text-xs">Cancel</button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex items-center justify-between mt-6 pt-5 border-t border-gray-200">
          <button
            onClick={back}
            disabled={!canBack}
            className="btn-secondary disabled:opacity-30"
          >
            <ChevronLeft className="w-4 h-4" /> Back
          </button>

          {canNext ? (
            <button onClick={next} className="btn-primary">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={() => generateReport('html')}
              disabled={!selectedId || generating !== null}
              className="btn-primary disabled:opacity-40"
            >
              {generating === 'html'
                ? <><Loader className="w-4 h-4 animate-spin" /> Generating…</>
                : <><Globe className="w-4 h-4" /> Generate HTML Report</>}
            </button>
          )}
        </div>

      </div>
    </div>
  )
}
