import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileText, Plus, Settings2, Download, RefreshCw } from 'lucide-react'
import {
  listGeneratedReports, listReportTemplates, reportDownloadUrl,
  type GeneratedReportRow, type ReportTemplate,
} from '../../api/client'
import { EmptyState, LoadingState } from '../../components/ui/page-state'

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

function regenerateUrl(r: GeneratedReportRow) {
  const p = new URLSearchParams()
  if (r.policy_id) p.set('policy', r.policy_id)
  if (r.template_id) p.set('template', r.template_id)
  if (r.analysis_run_id) p.set('analysis_run', r.analysis_run_id)
  const qs = p.toString()
  return `/reports/new${qs ? `?${qs}` : ''}`
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
            {templates.length === 0 && !loading && (
              <EmptyState
                icon={<Settings2 className="w-6 h-6" />}
                title="No report templates yet"
                description="Create reusable report templates for customer-ready and internal reporting."
                action={<button onClick={() => navigate('/reports/templates')} className="btn-secondary">Manage templates</button>}
                className="sm:col-span-2 lg:col-span-3 min-h-[180px]"
              />
            )}
          </div>
        </div>

        {/* Recent reports */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-700">Recent reports</h2>
            <button onClick={load} className="btn-secondary py-1 px-2 text-xs"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          </div>
          {loading ? (
            <LoadingState label="Loading reports..." />
          ) : reports.length === 0 ? (
            <EmptyState
              icon={<FileText className="w-6 h-6" />}
              title="No reports generated yet"
              description="Generate a report from an analyzed policy when you are ready to share findings."
              action={<button onClick={() => navigate('/reports/new')} className="btn-primary"><Plus className="w-4 h-4" /> Create report</button>}
            />
          ) : (
            <div className="table-shell">
              <table className="data-table">
                <thead>
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
                        <button onClick={() => navigate(regenerateUrl(r))} className="ml-3 text-gray-500 hover:text-gray-700 text-xs">Regenerate</button>
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
