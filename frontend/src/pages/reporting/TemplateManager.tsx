import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Copy, Trash2, Star, Pencil, ArrowLeft } from 'lucide-react'
import {
  listReportTemplates, cloneReportTemplate, deleteReportTemplate, setDefaultReportTemplate,
  type ReportTemplate,
} from '../../api/client'

export function TemplateManager() {
  const navigate = useNavigate()
  const [templates, setTemplates] = useState<ReportTemplate[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    listReportTemplates().then(d => setTemplates(d.templates)).catch(() => setTemplates([])).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const clone = async (id: string) => { await cloneReportTemplate(id); load() }
  const remove = async (id: string, name: string) => {
    if (!confirm(`Delete template "${name}"? This cannot be undone.`)) return
    await deleteReportTemplate(id); load()
  }
  const makeDefault = async (id: string) => { await setDefaultReportTemplate(id); load() }

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <button onClick={() => navigate('/reports')} className="text-gray-400 hover:text-gray-700"><ArrowLeft className="w-5 h-5" /></button>
          <div>
            <h1 className="page-title">Report Templates</h1>
            <p className="page-subtitle">Reusable, customer-facing and internal report templates.</p>
          </div>
        </div>
        <button onClick={() => navigate('/reports/templates/new')} className="btn-primary"><Plus className="w-4 h-4" /> New Template</button>
      </div>

      <div className="page-body">
        {loading ? (
          <div className="flex justify-center py-12"><div className="animate-spin w-7 h-7 border-b-2 border-blue-600 rounded-full" /></div>
        ) : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {templates.map(t => (
              <div key={t.id} className="card">
                <div className="flex items-start justify-between">
                  <h3 className="font-semibold text-sm">{t.name}</h3>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${t.is_customer_facing ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
                    {t.is_customer_facing ? 'Customer' : 'Internal'}</span>
                </div>
                <p className="text-xs text-gray-500 mt-1 line-clamp-2 min-h-[2rem]">{t.description}</p>
                <p className="text-[11px] text-gray-400 mt-1">
                  {t.sections.filter(s => s.enabled).length} sections · {t.default_export_format.toUpperCase()}
                  {t.is_default && <span className="ml-1 text-amber-600">★ default</span>}
                </p>
                <div className="flex flex-wrap gap-2 mt-3 text-xs">
                  <button onClick={() => navigate(`/reports/templates/${t.id}`)} className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800"><Pencil className="w-3.5 h-3.5" /> Edit</button>
                  <button onClick={() => clone(t.id)} className="inline-flex items-center gap-1 text-gray-600 hover:text-gray-800"><Copy className="w-3.5 h-3.5" /> Clone</button>
                  {!t.is_default && <button onClick={() => makeDefault(t.id)} className="inline-flex items-center gap-1 text-gray-600 hover:text-amber-600"><Star className="w-3.5 h-3.5" /> Default</button>}
                  <button onClick={() => remove(t.id, t.name)} className="inline-flex items-center gap-1 text-gray-400 hover:text-red-600"><Trash2 className="w-3.5 h-3.5" /> Delete</button>
                </div>
              </div>
            ))}
            {templates.length === 0 && <p className="text-sm text-gray-400">No templates yet — create one.</p>}
          </div>
        )}
      </div>
    </div>
  )
}
