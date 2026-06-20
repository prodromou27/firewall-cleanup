import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ChevronLeft, ChevronRight, ArrowUp, ArrowDown, FileText, Eye, Download, Check, Loader2,
} from 'lucide-react'
import {
  getPolicies, listReportTemplates, getReportSections, getReportFindingCategories,
  generateReport, reportDownloadUrl, type ReportTemplate, type ReportSectionDef,
} from '../../api/client'
import type { Policy } from '../../types'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const FORMATS: Array<{ key: string; label: string; hint: string }> = [
  { key: 'pdf', label: 'PDF', hint: 'Customer-ready final report' },
  { key: 'docx', label: 'Word / DOCX', hint: 'Editable report document' },
  { key: 'xlsx', label: 'Excel / XLSX', hint: 'Technical analysis workbook' },
  { key: 'html', label: 'HTML', hint: 'Web / printable report' },
  { key: 'csv', label: 'CSV', hint: 'Flat data export' },
  { key: 'json', label: 'JSON', hint: 'Structured export' },
]
const STEPS = ['Source', 'Template', 'Sections', 'Categories', 'Filters', 'Preview & Export']

export function ReportBuilder() {
  const navigate = useNavigate()
  const [step, setStep] = useState(0)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [templates, setTemplates] = useState<ReportTemplate[]>([])
  const [catalog, setCatalog] = useState<ReportSectionDef[]>([])
  const [categories, setCategories] = useState<Array<{ key: string; label: string }>>([])

  const [policyId, setPolicyId] = useState('')
  const [templateId, setTemplateId] = useState('')
  const [sections, setSections] = useState<string[]>([])
  const [selCats, setSelCats] = useState<string[]>([])
  const [severities, setSeverities] = useState<string[]>([])
  const [previewHtml, setPreviewHtml] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getPolicies({}).then(d => setPolicies(Array.isArray(d) ? d : [])).catch(() => {})
    listReportTemplates().then(d => setTemplates(d.templates)).catch(() => {})
    getReportSections().then(d => setCatalog(d.sections)).catch(() => {})
    getReportFindingCategories().then(d => setCategories(d.categories)).catch(() => {})
  }, [])

  // Apply template defaults when a template is chosen.
  useEffect(() => {
    const t = templates.find(x => x.id === templateId)
    if (!t) return
    setSections(t.sections.filter(s => s.enabled).sort((a, b) => a.display_order - b.display_order).map(s => s.section_key))
    setSelCats(t.default_finding_categories || [])
  }, [templateId, templates])

  const secName = useCallback((k: string) => catalog.find(c => c.key === k)?.name || k, [catalog])

  const move = (i: number, dir: -1 | 1) => {
    setSections(prev => {
      const arr = [...prev]; const j = i + dir
      if (j < 0 || j >= arr.length) return prev
      ;[arr[i], arr[j]] = [arr[j], arr[i]]; return arr
    })
  }
  const toggleSection = (k: string) =>
    setSections(prev => prev.includes(k) ? prev.filter(s => s !== k) : [...prev, k])
  const toggleCat = (k: string) =>
    setSelCats(prev => prev.includes(k) ? prev.filter(s => s !== k) : [...prev, k])
  const toggleSev = (s: string) =>
    setSeverities(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])

  const body = () => ({
    policy_id: policyId,
    template_id: templateId || undefined,
    sections,
    finding_categories: selCats.length ? selCats : undefined,
    filters: severities.length ? { severities } : {},
  })

  const doPreview = async () => {
    setBusy(true); setError(''); setPreviewHtml('')
    try {
      const res = await fetch('/api/reports/preview', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body(), export_format: 'html' }),
      })
      if (!res.ok) throw new Error(`Preview failed (${res.status})`)
      setPreviewHtml(await res.text())
    } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }

  const doExport = async (fmt: string) => {
    setBusy(true); setError('')
    try {
      const r = await generateReport({ ...body(), export_format: fmt })
      const res = await fetch(reportDownloadUrl(r.id), { credentials: 'include' })
      if (!res.ok) throw new Error(`Download failed (${res.status})`)
      const blob = await res.blob()
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
      a.download = r.file_name; a.click(); URL.revokeObjectURL(a.href)
    } catch (e) { setError((e as Error).message) } finally { setBusy(false) }
  }

  const canNext = (step === 0 && policyId) || (step === 1 && true) || step >= 2
  const selectedPolicy = policies.find(p => p.id === policyId)

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Build Report</h1>
          <p className="page-subtitle">Read-only report — generated from existing analysis data.</p>
        </div>
        <button onClick={() => navigate('/reports')} className="btn-secondary">Cancel</button>
      </div>

      <div className="page-body">
        {/* Stepper */}
        <div className="flex flex-wrap gap-2 mb-5">
          {STEPS.map((s, i) => (
            <button key={s} onClick={() => i <= step && setStep(i)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border
                ${i === step ? 'bg-blue-600 text-white border-blue-600'
                  : i < step ? 'bg-blue-50 text-blue-700 border-blue-200' : 'bg-white text-gray-400 border-gray-200'}`}>
              {i < step ? <Check className="w-3 h-3" /> : <span>{i + 1}</span>} {s}
            </button>
          ))}
        </div>

        {error && <div className="mb-4 rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error}</div>}

        {/* Step 0: Source */}
        {step === 0 && (
          <div className="card max-w-xl">
            <h3 className="font-semibold mb-3">Select firewall / policy</h3>
            <select value={policyId} onChange={e => setPolicyId(e.target.value)}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm bg-gray-50 focus:bg-white">
              <option value="">Choose a policy…</option>
              {policies.map(p => (
                <option key={p.id} value={p.id}>{p.firewall_name} · {p.vendor}{p.customer_name ? ` · ${p.customer_name}` : ''}</option>
              ))}
            </select>
          </div>
        )}

        {/* Step 1: Template */}
        {step === 1 && (
          <div className="grid sm:grid-cols-2 gap-3">
            {templates.map(t => (
              <button key={t.id} onClick={() => setTemplateId(t.id)}
                className={`card text-left ${templateId === t.id ? 'ring-2 ring-blue-500' : 'hover:border-blue-300'}`}>
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">{t.name}</h3>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${t.is_customer_facing ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
                    {t.is_customer_facing ? 'Customer' : 'Internal'}</span>
                </div>
                <p className="text-xs text-gray-500 mt-1">{t.description}</p>
                <p className="text-[11px] text-gray-400 mt-2">{t.sections.filter(s => s.enabled).length} sections · default {t.default_export_format.toUpperCase()}</p>
              </button>
            ))}
            <button onClick={() => { setTemplateId(''); setSections(catalog.filter(c => c.default).map(c => c.key)) }}
              className={`card text-left ${!templateId ? 'ring-2 ring-blue-500' : 'hover:border-blue-300'}`}>
              <h3 className="font-semibold">No template (defaults)</h3>
              <p className="text-xs text-gray-500 mt-1">Start from the default section set.</p>
            </button>
          </div>
        )}

        {/* Step 2: Sections (reorder + toggle) */}
        {step === 2 && (
          <div className="grid md:grid-cols-2 gap-4">
            <div className="card">
              <h3 className="font-semibold mb-2">Included sections (in order)</h3>
              <div className="space-y-1">
                {sections.map((k, i) => (
                  <div key={k} className="flex items-center gap-2 border border-gray-100 rounded-lg px-2 py-1.5">
                    <span className="text-xs text-gray-400 w-5">{i + 1}</span>
                    <span className="flex-1 text-sm">{secName(k)}</span>
                    <button onClick={() => move(i, -1)} disabled={i === 0} className="text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowUp className="w-4 h-4" /></button>
                    <button onClick={() => move(i, 1)} disabled={i === sections.length - 1} className="text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowDown className="w-4 h-4" /></button>
                    <button onClick={() => toggleSection(k)} className="text-gray-300 hover:text-red-500">✕</button>
                  </div>
                ))}
                {sections.length === 0 && <p className="text-sm text-gray-400">No sections selected.</p>}
              </div>
            </div>
            <div className="card">
              <h3 className="font-semibold mb-2">Section library</h3>
              <div className="space-y-1 max-h-[420px] overflow-y-auto">
                {catalog.map(c => (
                  <label key={c.key} className="flex items-center gap-2 text-sm py-0.5">
                    <input type="checkbox" checked={sections.includes(c.key)} onChange={() => toggleSection(c.key)} />
                    <span>{c.name}</span><span className="text-[10px] text-gray-400">{c.group}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Step 3: Finding categories */}
        {step === 3 && (
          <div className="card">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold">Finding categories <span className="text-xs text-gray-400">(none = all)</span></h3>
              <div className="flex gap-2 text-xs">
                <button onClick={() => setSelCats(categories.map(c => c.key))} className="text-blue-600">Select all</button>
                <button onClick={() => setSelCats([])} className="text-gray-500">Clear</button>
              </div>
            </div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
              {categories.map(c => (
                <label key={c.key} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={selCats.includes(c.key)} onChange={() => toggleCat(c.key)} />{c.label}
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Step 4: Filters */}
        {step === 4 && (
          <div className="card max-w-lg">
            <h3 className="font-semibold mb-2">Severity filter <span className="text-xs text-gray-400">(none = all)</span></h3>
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.map(s => (
                <button key={s} onClick={() => toggleSev(s)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border ${severities.includes(s) ? 'bg-blue-600 text-white border-blue-600' : 'border-gray-200 text-gray-600'}`}>{s}</button>
              ))}
            </div>
          </div>
        )}

        {/* Step 5: Preview & Export */}
        {step === 5 && (
          <div className="space-y-4">
            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold">Preview {selectedPolicy ? `· ${selectedPolicy.firewall_name}` : ''}</h3>
                <button onClick={doPreview} disabled={busy} className="btn-secondary">
                  {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />} Refresh preview
                </button>
              </div>
              {previewHtml
                ? <iframe title="preview" srcDoc={previewHtml} className="w-full h-[520px] border border-gray-200 rounded-lg bg-white" />
                : <div className="text-sm text-gray-400 py-10 text-center">Click “Refresh preview” to render the report.</div>}
            </div>
            <div className="card">
              <h3 className="font-semibold mb-3">Export</h3>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {FORMATS.map(f => (
                  <button key={f.key} onClick={() => doExport(f.key)} disabled={busy || !policyId}
                    className="flex items-start gap-2 border border-gray-200 rounded-lg px-3 py-2.5 text-left hover:border-blue-400 disabled:opacity-50">
                    <Download className="w-4 h-4 mt-0.5 text-blue-600" />
                    <span><span className="block text-sm font-semibold">{f.label}</span><span className="block text-[11px] text-gray-500">{f.hint}</span></span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Nav */}
        <div className="flex justify-between mt-5">
          <button onClick={() => setStep(s => Math.max(0, s - 1))} disabled={step === 0}
            className="btn-secondary disabled:opacity-40"><ChevronLeft className="w-4 h-4" /> Back</button>
          {step < STEPS.length - 1 && (
            <button onClick={() => { if (step === 4) doPreview(); setStep(s => s + 1) }} disabled={!canNext}
              className="btn-primary disabled:opacity-40">Next <ChevronRight className="w-4 h-4" /></button>
          )}
        </div>
      </div>
    </div>
  )
}
