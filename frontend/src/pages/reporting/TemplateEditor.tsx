import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ArrowUp, ArrowDown, Save, Loader2 } from 'lucide-react'
import {
  getReportTemplate, createReportTemplate, updateReportTemplate, getReportSections,
  getReportFindingCategories, getReportPlaceholders, uploadReportLogo,
  type ReportTemplate, type TemplateSection, type ReportSectionDef,
} from '../../api/client'

const BLANK: Partial<ReportTemplate> = {
  name: 'New Template', description: '', template_type: 'technical', audience: 'internal',
  is_customer_facing: false, default_export_format: 'pdf', default_detail_level: 'standard',
  branding_config: {}, cover_page_config: {}, introduction_text: '', methodology_text: '',
  disclaimer_text: '', footer_text: '', default_finding_categories: [], sections: [],
}

export function TemplateEditor() {
  const { id } = useParams<{ id: string }>()
  const isNew = id === 'new'
  const navigate = useNavigate()
  const [t, setT] = useState<Partial<ReportTemplate>>(BLANK)
  const [catalog, setCatalog] = useState<ReportSectionDef[]>([])
  const [categories, setCategories] = useState<Array<{ key: string; label: string }>>([])
  const [placeholders, setPlaceholders] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getReportSections().then(d => setCatalog(d.sections)).catch(() => {})
    getReportFindingCategories().then(d => setCategories(d.categories)).catch(() => {})
    getReportPlaceholders().then(d => setPlaceholders(d.placeholders)).catch(() => {})
    if (isNew) {
      getReportSections().then(d => {
        setT({ ...BLANK, sections: d.default_sections.map((k, i) => ({ section_key: k, enabled: true, display_order: i })) })
        setLoaded(true)
      })
    } else if (id) {
      getReportTemplate(id).then(tp => { setT(tp); setLoaded(true) }).catch(() => setError('Template not found'))
    }
  }, [id, isNew])

  const set = (patch: Partial<ReportTemplate>) => setT(prev => ({ ...prev, ...patch }))
  const secName = useCallback((k: string) => catalog.find(c => c.key === k)?.name || k, [catalog])
  const sections = (t.sections || []) as TemplateSection[]

  const reorder = (i: number, dir: -1 | 1) => {
    const arr = [...sections]; const j = i + dir
    if (j < 0 || j >= arr.length) return
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
    set({ sections: arr.map((s, idx) => ({ ...s, display_order: idx })) })
  }
  const toggleEnabled = (i: number) => {
    const arr = [...sections]; arr[i] = { ...arr[i], enabled: !arr[i].enabled }; set({ sections: arr })
  }
  const addSection = (key: string) => {
    if (sections.some(s => s.section_key === key)) return
    set({ sections: [...sections, { section_key: key, enabled: true, display_order: sections.length }] })
  }
  const addCustom = () => {
    const key = `custom_${Date.now()}`
    set({ sections: [...sections, { section_key: key, section_type: 'custom_text', section_name: 'Custom Section', enabled: true, display_order: sections.length, custom_text: '' }] })
  }
  const setCustomText = (i: number, text: string) => {
    const arr = [...sections]; arr[i] = { ...arr[i], custom_text: text }; set({ sections: arr })
  }
  const toggleCat = (k: string) => {
    const cur = t.default_finding_categories || []
    set({ default_finding_categories: cur.includes(k) ? cur.filter(x => x !== k) : [...cur, k] })
  }

  const save = async () => {
    setSaving(true); setError('')
    try {
      const body = { ...t, sections: sections.map((s, i) => ({ ...s, display_order: i })) }
      if (isNew) { const created = await createReportTemplate(body); navigate(`/reports/templates/${created.id}`) }
      else { await updateReportTemplate(id!, body) }
    } catch (e: unknown) {
      setError((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Save failed')
    } finally { setSaving(false) }
  }

  const bc = (t.branding_config || {}) as Record<string, string>
  const cc = (t.cover_page_config || {}) as Record<string, string>
  const setBrand = (k: string, v: string) => set({ branding_config: { ...bc, [k]: v } })
  const setCover = (k: string, v: string) => set({ cover_page_config: { ...cc, [k]: v } })
  const [logoPreview, setLogoPreview] = useState<Record<string, string>>({})
  const uploadLogo = async (slot: 'company_logo' | 'customer_logo', file?: File) => {
    if (!file) return
    try {
      const r = await uploadReportLogo(file)
      setBrand(slot, r.logo_ref)
      setLogoPreview(p => ({ ...p, [slot]: r.data_uri }))
    } catch { setError('Logo upload failed (must be an image under 2 MB).') }
  }

  if (!loaded && !error) return <div className="page-body"><div className="animate-spin w-7 h-7 border-b-2 border-blue-600 rounded-full mx-auto mt-16" /></div>

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <button onClick={() => navigate('/reports/templates')} className="text-gray-400 hover:text-gray-700"><ArrowLeft className="w-5 h-5" /></button>
          <div>
            <h1 className="page-title">{isNew ? 'New Template' : 'Edit Template'}</h1>
            <p className="page-subtitle">Sections, branding, and editable narrative text with placeholders.</p>
          </div>
        </div>
        <button onClick={save} disabled={saving} className="btn-primary">{saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save</button>
      </div>

      <div className="page-body space-y-4">
        {error && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error}</div>}

        {/* Basics */}
        <div className="card grid sm:grid-cols-2 gap-3">
          <label className="text-sm">Name<input className="inp" value={t.name || ''} onChange={e => set({ name: e.target.value })} /></label>
          <label className="text-sm">Type
            <select className="inp" value={t.template_type} onChange={e => set({ template_type: e.target.value })}>
              {['technical', 'executive', 'cleanup', 'exposure', 'custom'].map(x => <option key={x}>{x}</option>)}
            </select></label>
          <label className="text-sm">Audience
            <select className="inp" value={t.audience} onChange={e => set({ audience: e.target.value, is_customer_facing: e.target.value === 'customer' })}>
              <option value="internal">internal</option><option value="customer">customer</option>
            </select></label>
          <label className="text-sm">Default export
            <select className="inp" value={t.default_export_format} onChange={e => set({ default_export_format: e.target.value })}>
              {['pdf', 'docx', 'xlsx', 'html', 'csv', 'json'].map(x => <option key={x}>{x}</option>)}
            </select></label>
          <label className="text-sm sm:col-span-2">Description<input className="inp" value={t.description || ''} onChange={e => set({ description: e.target.value })} /></label>
        </div>

        {/* Sections */}
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-semibold">Sections (order & enable)</h3>
            <button onClick={addCustom} className="btn-secondary py-1 px-2 text-xs">+ Custom text section</button>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-1">
              {sections.map((s, i) => (
                <div key={s.section_key} className="border border-gray-100 rounded-lg px-2 py-1.5">
                  <div className="flex items-center gap-2">
                    <input type="checkbox" checked={s.enabled} onChange={() => toggleEnabled(i)} />
                    <span className="flex-1 text-sm">{s.section_name || secName(s.section_key)}</span>
                    <button onClick={() => reorder(i, -1)} disabled={i === 0} className="text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowUp className="w-4 h-4" /></button>
                    <button onClick={() => reorder(i, 1)} disabled={i === sections.length - 1} className="text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowDown className="w-4 h-4" /></button>
                  </div>
                  {s.section_type === 'custom_text' && (
                    <textarea className="inp mt-1 text-xs font-mono" rows={2} placeholder="Custom section text (supports placeholders)"
                      value={s.custom_text || ''} onChange={e => setCustomText(i, e.target.value)} />
                  )}
                </div>
              ))}
            </div>
            <div>
              <p className="text-xs text-gray-400 mb-1">Add from library</p>
              <div className="space-y-0.5 max-h-72 overflow-y-auto">
                {catalog.filter(c => !sections.some(s => s.section_key === c.key)).map(c => (
                  <button key={c.key} onClick={() => addSection(c.key)} className="block w-full text-left text-sm py-0.5 text-blue-600 hover:underline">+ {c.name}</button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Narrative text + placeholders */}
        <div className="card">
          <h3 className="font-semibold mb-1">Narrative text</h3>
          <p className="text-[11px] text-gray-400 mb-2">Placeholders: {placeholders.map(p => <code key={p} className="bg-gray-100 px-1 rounded mr-1">{`{{${p}}}`}</code>)}</p>
          {([['introduction_text', 'Introduction'], ['methodology_text', 'Methodology'], ['disclaimer_text', 'Disclaimer'], ['footer_text', 'Footer']] as const).map(([k, label]) => (
            <label key={k} className="block text-sm mb-2">{label}
              <textarea className="inp font-mono text-xs" rows={k === 'footer_text' ? 1 : 3}
                value={(t[k] as string) || ''} onChange={e => set({ [k]: e.target.value } as Partial<ReportTemplate>)} /></label>
          ))}
        </div>

        {/* Branding / cover */}
        <div className="card grid sm:grid-cols-2 gap-3">
          <h3 className="font-semibold sm:col-span-2">Branding & cover page</h3>
          <label className="text-sm">Company name<input className="inp" value={bc.company_name || ''} onChange={e => setBrand('company_name', e.target.value)} /></label>
          <label className="text-sm">Confidentiality<input className="inp" value={bc.confidentiality || ''} onChange={e => setBrand('confidentiality', e.target.value)} placeholder="Confidential" /></label>
          <label className="text-sm">Accent color<input className="inp" type="text" value={bc.accent_color || ''} onChange={e => setBrand('accent_color', e.target.value)} placeholder="#1e3a5f" /></label>
          <label className="text-sm">Report title<input className="inp" value={bc.report_title || ''} onChange={e => setBrand('report_title', e.target.value)} placeholder="{{firewall_name}} Policy Review" /></label>
          <label className="text-sm">Cover subtitle<input className="inp" value={cc.cover_subtitle || ''} onChange={e => setCover('cover_subtitle', e.target.value)} /></label>
          <label className="text-sm">Prepared by<input className="inp" value={cc.prepared_by || ''} onChange={e => setCover('prepared_by', e.target.value)} /></label>
          {(['company_logo', 'customer_logo'] as const).map(slot => (
            <div key={slot} className="text-sm">
              <span className="capitalize">{slot.replace('_', ' ')}</span>
              <div className="flex items-center gap-3 mt-1">
                {(logoPreview[slot] || bc[slot]) && (
                  <img src={logoPreview[slot] || ''} alt="" className="h-10 max-w-[120px] object-contain border border-gray-100 rounded" />
                )}
                {!logoPreview[slot] && bc[slot] && <span className="text-[11px] text-gray-400">logo set</span>}
                <input type="file" accept="image/*" className="text-xs"
                  onChange={e => uploadLogo(slot, e.target.files?.[0])} />
                {bc[slot] && <button type="button" onClick={() => { setBrand(slot, ''); setLogoPreview(p => ({ ...p, [slot]: '' })) }} className="text-xs text-red-500">remove</button>}
              </div>
            </div>
          ))}
        </div>

        {/* Default categories */}
        <div className="card">
          <h3 className="font-semibold mb-2">Default finding categories <span className="text-xs text-gray-400">(none = all)</span></h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
            {categories.map(c => (
              <label key={c.key} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={(t.default_finding_categories || []).includes(c.key)} onChange={() => toggleCat(c.key)} />{c.label}
              </label>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
