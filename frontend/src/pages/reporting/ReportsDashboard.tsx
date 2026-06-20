import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileText, Plus, Settings2, Download, RefreshCw } from 'lucide-react'
import {
  listGeneratedReports, listReportTemplates, reportDownloadUrl,
  type GeneratedReportRow, type ReportTemplate,
} from '../../api/client'

const FMT_LABEL: Record<string, string> = {
  pdf: 'PDF', docx: 'Word', xlsx: 'Excel', html: 'HTML', csv: 'CSV', json: 'JSON',
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso); return isNaN(d.getTime()) ? iso : d.toLocaleString()
}

async function download(id: string, name: string) {
  const res = await fetch(reportDownloadUrl(id), { credentials: 'include' })
  if (!res.ok) return
  const blob = await res.blob()
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click()
  URL.revokeObjectURL(a.href)
}

export function ReportsDashboard() {
  const navigate = useNavigate()
  const [reports, setReports] = useState<GeneratedReportRow[]>([])
  const [templates, setTemplates] = useState<ReportTemplate[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    Promise.all([
      listGeneratedReports().then(d => setReports(d.reports)).catch(() => setReports([])),
      listReportTemplates().then(d => setTemplates(d.templates)).catch(() => setTemplates([])),
    ]).finally(() => setLoading(false))
  }
  useEffect(load, [])

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Generate customer-ready and internal reports from existing analysis data.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => navigate('/reports/templates')} className="btn-secondary"><Settings2 className="w-4 h-4" /> Manage Templates</button>
          <button onClick={() => navigate('/reports/new')} className="btn-primary"><Plus className="w-4 h-4" /> Create Report</button>
        </div>
      </div>

      <div className="page-body space-y-6">
        {/* Templates */}
        <div>
          <h2 className="text-sm font-semibold text-gray-700 mb-2">Templates</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {templates.map(t => (
              <button key={t.id} onClick={() => navigate(`/reports/templates/${t.id}`)} className="card text-left hover:border-blue-300">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">{t.name}</h3>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${t.is_customer_facing ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
                    {t.is_customer_facing ? 'Customer' : 'Internal'}{t.is_default ? ' · default' : ''}</span>
                </div>
                <p className="text-xs text-gray-500 mt-1 line-clamp-2">{t.description}</p>
                <p className="text-[11px] text-gray-400 mt-2">{t.sections.filter(s => s.enabled).length} sections · {t.default_export_format.toUpperCase()}</p>
              </button>
            ))}
            {templates.length === 0 && !loading && <p className="text-sm text-gray-400">No templates yet.</p>}
          </div>
        </div>

        {/* Recent reports */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-700">Recent reports</h2>
            <button onClick={load} className="btn-secondary py-1 px-2 text-xs"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          </div>
          {loading ? (
            <div className="flex justify-center py-12"><div className="animate-spin w-7 h-7 border-b-2 border-blue-600 rounded-full" /></div>
          ) : reports.length === 0 ? (
            <div className="card text-center py-10">
              <FileText className="w-9 h-9 text-gray-300 mx-auto mb-2" />
              <p className="text-gray-500 text-sm">No reports generated yet.</p>
              <button onClick={() => navigate('/reports/new')} className="btn-primary mt-3"><Plus className="w-4 h-4" /> Create your first report</button>
            </div>
          ) : (
            <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200 text-left text-[11px] uppercase text-gray-400">
                  <tr><th className="px-4 py-2.5">Type</th><th className="px-4 py-2.5">Firewall</th>
                    <th className="px-4 py-2.5">Format</th><th className="px-4 py-2.5">Generated</th>
                    <th className="px-4 py-2.5">By</th><th className="px-4 py-2.5"></th></tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {reports.map(r => (
                    <tr key={r.id} className="hover:bg-gray-50/70">
                      <td className="px-4 py-2.5 capitalize">{r.report_type}</td>
                      <td className="px-4 py-2.5">{r.firewall_name || '—'}</td>
                      <td className="px-4 py-2.5"><span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-blue-50 text-blue-700">{FMT_LABEL[r.export_format] || r.export_format}</span></td>
                      <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{fmtDate(r.generated_at)}</td>
                      <td className="px-4 py-2.5 text-gray-500">{r.generated_by || '—'}</td>
                      <td className="px-4 py-2.5 text-right whitespace-nowrap">
                        <button onClick={() => download(r.id, r.file_name)} className="text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 text-xs"><Download className="w-3.5 h-3.5" /> Download</button>
                        <button onClick={() => navigate(`/reports/new?policy=${r.policy_id || ''}&template=${r.template_id || ''}`)} className="ml-3 text-gray-500 hover:text-gray-700 text-xs">Regenerate</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
