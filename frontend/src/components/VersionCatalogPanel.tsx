import { useEffect, useState } from 'react'
import { Plus, Trash2, Upload } from 'lucide-react'
import {
  listVersionCatalog, createVersionCatalogEntry, deleteVersionCatalogEntry,
  importVersionCatalog, type VersionCatalogEntry,
} from '../api/client'

const BLANK: VersionCatalogEntry = { vendor: 'CheckPoint', release_train: '', recommended_version: '', support_status: 'supported', eol_versions: [] }

export function VersionCatalogPanel() {
  const [entries, setEntries] = useState<VersionCatalogEntry[]>([])
  const [draft, setDraft] = useState<VersionCatalogEntry>(BLANK)
  const [error, setError] = useState('')

  const load = () => listVersionCatalog().then(setEntries).catch(() => setError('Failed to load catalog.'))
  useEffect(() => { load() }, [])

  const add = async () => {
    if (!draft.vendor) return
    try { await createVersionCatalogEntry({ ...draft, eol_versions: (draft.eol_versions || []) }); setDraft(BLANK); load() }
    catch { setError('Could not add entry (requires manage-settings permission).') }
  }
  const remove = async (id?: string) => { if (id) { await deleteVersionCatalogEntry(id); load() } }
  const onImport = async (file?: File) => {
    if (!file) return
    try {
      const json = JSON.parse(await file.text())
      await importVersionCatalog(Array.isArray(json) ? json : [json], false)
      load()
    } catch { setError('Import failed — expected a JSON array of catalog entries.') }
  }

  return (
    <div className="space-y-4">
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-800">
        Manually-managed firewall version catalog. Used by version intelligence to flag outdated / end-of-support
        firmware. No internet access is used — import or edit entries here.
      </div>
      {error && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error}</div>}

      {/* Add row */}
      <div className="card grid sm:grid-cols-6 gap-2 items-end">
        <label className="text-xs">Vendor
          <select className="inp" value={draft.vendor} onChange={e => setDraft({ ...draft, vendor: e.target.value })}>
            {['FortiGate', 'CheckPoint', 'PaloAlto', 'CiscoASA', 'HuaweiUSG'].map(v => <option key={v}>{v}</option>)}
          </select></label>
        <label className="text-xs">Release train<input className="inp" placeholder="R81" value={draft.release_train || ''} onChange={e => setDraft({ ...draft, release_train: e.target.value })} /></label>
        <label className="text-xs">Recommended<input className="inp" placeholder="R81.20" value={draft.recommended_version || ''} onChange={e => setDraft({ ...draft, recommended_version: e.target.value })} /></label>
        <label className="text-xs">Support status
          <select className="inp" value={draft.support_status || 'supported'} onChange={e => setDraft({ ...draft, support_status: e.target.value })}>
            {['supported', 'extended', 'end-of-support'].map(v => <option key={v}>{v}</option>)}
          </select></label>
        <label className="text-xs">Advisory URL<input className="inp" value={draft.advisory_url || ''} onChange={e => setDraft({ ...draft, advisory_url: e.target.value })} /></label>
        <button onClick={add} className="btn-primary justify-center"><Plus className="w-4 h-4" /> Add</button>
      </div>

      {/* Import */}
      <label className="inline-flex items-center gap-2 text-sm text-blue-600 cursor-pointer">
        <Upload className="w-4 h-4" /> Import JSON
        <input type="file" accept="application/json" className="hidden" onChange={e => onImport(e.target.files?.[0])} />
      </label>

      {/* Table */}
      <div className="card overflow-x-auto">
        {entries.length === 0 ? <p className="text-sm text-gray-400">No catalog entries yet.</p> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-gray-500 border-b">
              <th className="py-1.5 pr-3">Vendor</th><th className="py-1.5 pr-3">Train</th>
              <th className="py-1.5 pr-3">Recommended</th><th className="py-1.5 pr-3">Status</th>
              <th className="py-1.5 pr-3">EOL</th><th></th>
            </tr></thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} className="border-b border-gray-50">
                  <td className="py-1.5 pr-3">{e.vendor}</td>
                  <td className="py-1.5 pr-3">{e.release_train || '—'}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{e.recommended_version || '—'}</td>
                  <td className="py-1.5 pr-3">{e.support_status || '—'}</td>
                  <td className="py-1.5 pr-3 text-xs text-gray-500">{(e.eol_versions || []).join(', ') || '—'}</td>
                  <td className="py-1.5"><button onClick={() => remove(e.id)} className="text-red-500 hover:text-red-700"><Trash2 className="w-4 h-4" /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
