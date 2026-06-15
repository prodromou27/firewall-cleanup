import { useEffect, useState, useCallback } from 'react'
import { ScrollText, Search, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { getAuditEvents, type AuditEvent } from '../api/client'

/** Human label + accent colour per event family. */
const EVENT_STYLES: Array<{ prefix: string; label: string; cls: string }> = [
  { prefix: 'auth.', label: 'Auth', cls: 'bg-indigo-100 text-indigo-700' },
  { prefix: 'user.', label: 'User', cls: 'bg-purple-100 text-purple-700' },
  { prefix: 'customer.', label: 'Customer', cls: 'bg-teal-100 text-teal-700' },
  { prefix: 'device.', label: 'Device', cls: 'bg-blue-100 text-blue-700' },
  { prefix: 'policy.', label: 'Policy', cls: 'bg-amber-100 text-amber-700' },
  { prefix: 'sync.', label: 'Sync', cls: 'bg-green-100 text-green-700' },
]

function eventStyle(event: string) {
  return EVENT_STYLES.find(s => event.startsWith(s.prefix)) || { label: 'Other', cls: 'bg-gray-100 text-gray-600' }
}

function fmtTs(ts: string | null) {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

export function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [eventFilter, setEventFilter] = useState('')
  const [actor, setActor] = useState('')
  const [since, setSince] = useState('')
  const pageSize = 50

  const load = useCallback(() => {
    setLoading(true)
    const p: Record<string, string | number> = { page, page_size: pageSize }
    if (eventFilter) p.event = eventFilter
    if (actor.trim()) p.actor = actor.trim()
    if (since) p.since = since
    getAuditEvents(p)
      .then(r => { setEvents(r.events); setTotal(r.total) })
      .catch(() => { setEvents([]); setTotal(0) })
      .finally(() => setLoading(false))
  }, [page, eventFilter, actor, since])

  useEffect(() => { load() }, [load])

  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const setFilter = (fn: () => void) => { fn(); setPage(1) }

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Audit Trail</h1>
          <p className="page-subtitle">{total.toLocaleString()} recorded events · append-only activity log</p>
        </div>
        <button onClick={load} className="btn-secondary"><RefreshCw className="w-4 h-4" /> Refresh</button>
      </div>

      <div className="page-body">
        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-5 p-3 bg-white rounded-xl border border-gray-200 shadow-sm">
          <select
            value={eventFilter}
            onChange={e => setFilter(() => setEventFilter(e.target.value))}
            className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white"
          >
            <option value="">All event types</option>
            {EVENT_STYLES.map(s => <option key={s.prefix} value={s.prefix}>{s.label}</option>)}
          </select>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              value={actor}
              onChange={e => setFilter(() => setActor(e.target.value))}
              placeholder="Filter by actor email…"
              className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm w-60 bg-gray-50 focus:bg-white"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-500">
            Since
            <input
              type="date"
              value={since}
              onChange={e => setFilter(() => setSince(e.target.value))}
              className="border border-gray-200 rounded-lg px-2 py-1.5 text-sm bg-gray-50 focus:bg-white"
            />
          </label>
          {(eventFilter || actor || since) && (
            <button
              onClick={() => setFilter(() => { setEventFilter(''); setActor(''); setSince('') })}
              className="text-xs text-blue-500 hover:text-blue-700 self-center"
            >
              Clear filters
            </button>
          )}
        </div>

        {loading ? (
          <div className="flex justify-center py-16"><div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" /></div>
        ) : events.length === 0 ? (
          <div className="card text-center py-12">
            <ScrollText className="w-10 h-10 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No audit events match the current filters.</p>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr className="text-left text-[11px] font-semibold text-gray-400 uppercase tracking-wide">
                  <th className="px-4 py-2.5">When</th>
                  <th className="px-4 py-2.5">Event</th>
                  <th className="px-4 py-2.5">Actor</th>
                  <th className="px-4 py-2.5">Target</th>
                  <th className="px-4 py-2.5">Source IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {events.map(e => {
                  const st = eventStyle(e.event)
                  return (
                    <tr key={e.id} className="hover:bg-gray-50/80">
                      <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{fmtTs(e.ts)}</td>
                      <td className="px-4 py-2.5">
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${st.cls}`}>{st.label}</span>
                        <span className="ml-2 font-mono text-xs text-gray-700">{e.event}</span>
                      </td>
                      <td className="px-4 py-2.5 text-gray-600">{e.actor_email || (e.user_id ? e.user_id.slice(0, 8) : '—')}</td>
                      <td className="px-4 py-2.5 text-gray-500 text-xs">
                        {e.target_type ? <span className="font-medium text-gray-600">{e.target_type}</span> : ''}
                        {e.target_id ? <span className="font-mono ml-1">{e.target_id.slice(0, 8)}</span> : (!e.target_type && '—')}
                      </td>
                      <td className="px-4 py-2.5 text-gray-400 font-mono text-xs">{e.source_ip || '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>

            {pageCount > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 text-sm">
                <span className="text-gray-500">Page {page} of {pageCount} ({total.toLocaleString()} events)</span>
                <div className="flex gap-2">
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    className="btn-secondary py-1 px-3 flex items-center gap-1"><ChevronLeft className="w-4 h-4" /> Prev</button>
                  <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} disabled={page === pageCount}
                    className="btn-secondary py-1 px-3 flex items-center gap-1">Next <ChevronRight className="w-4 h-4" /></button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
