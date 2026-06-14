import { useEffect, useState, useCallback, useMemo } from 'react'
import { useSearchParams, useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import { Package, Search, ArrowUp, ArrowDown, ArrowUpDown } from 'lucide-react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from '@tanstack/react-table'
import { getObjects, getPolicies } from '../api/client'
import type { FirewallObject, Policy } from '../types'
import { clsx } from 'clsx'

const CATEGORIES = [
  { value: 'unused', label: '📦 Unused' },
  { value: 'duplicates', label: '🧬 Duplicates' },
  { value: 'empty_groups', label: '🫙 Empty Groups' },
  { value: 'large_groups', label: '📚 Large Groups' },
]

function ObjectTypeChip({ type }: { type: string }) {
  const colors: Record<string, string> = {
    host: 'bg-blue-100 text-blue-700',
    network: 'bg-green-100 text-green-700',
    range: 'bg-purple-100 text-purple-700',
    group: 'bg-orange-100 text-orange-700',
    service: 'bg-teal-100 text-teal-700',
    'service-group': 'bg-pink-100 text-pink-700',
    fqdn: 'bg-yellow-100 text-yellow-700',
  }
  return (
    <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded', colors[type] || 'bg-gray-100 text-gray-600')}>
      {type}
    </span>
  )
}

function StatusBadges({ obj }: { obj: FirewallObject }) {
  return (
    <div className="flex flex-wrap gap-1">
      {obj.is_unused && (
        <span className="text-xs font-semibold text-orange-700 bg-orange-100 px-2 py-0.5 rounded">Unused</span>
      )}
      {obj.is_duplicate && (
        <span className="text-xs font-semibold text-purple-700 bg-purple-100 px-2 py-0.5 rounded">Duplicate</span>
      )}
      {obj.is_empty_group && (
        <span className="text-xs font-semibold text-red-700 bg-red-100 px-2 py-0.5 rounded">Empty</span>
      )}
      {obj.is_large_group && (
        <span className="text-xs font-semibold text-blue-700 bg-blue-100 px-2 py-0.5 rounded">Large</span>
      )}
      {!obj.is_unused && !obj.is_duplicate && !obj.is_empty_group && !obj.is_large_group && (
        <span className="text-xs text-gray-400">In use</span>
      )}
    </div>
  )
}

function valueText(obj: FirewallObject): string {
  return obj.value || (obj.object_type.includes('service') && obj.protocol
    ? `${obj.protocol}/${obj.port_start}-${obj.port_end}`
    : '')
}

const col = createColumnHelper<FirewallObject>()

export function Objects() {
  const [searchParams, setSearchParams] = useSearchParams()
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id || ''
  const [objects, setObjects] = useState<FirewallObject[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [sorting, setSorting] = useState<SortingState>([])

  const policyId = searchParams.get('policy_id') || ''
  const objectType = searchParams.get('object_type') || ''
  const category = searchParams.get('category') || ''

  const load = useCallback(() => {
    setLoading(true)
    const p: Record<string, string | number | boolean> = { page, page_size: 100 }
    if (policyId) p.policy_id = policyId
    else if (customerId) p.customer_id = customerId
    if (objectType) p.object_type = objectType
    if (search) p.search = search
    if (category) p.category = category
    getObjects(p as Record<string, string | number>)
      .then(r => {
        setObjects(r.objects)
        setTotal(r.total)
      })
      .finally(() => setLoading(false))
  }, [page, policyId, customerId, objectType, search, category])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const pp: Record<string, string> = {}
    if (customerId) pp.customer_id = customerId
    getPolicies(pp).then(data => setPolicies(Array.isArray(data) ? data : []))
  }, [customerId])

  const setFilter = (key: string, val: string) => {
    const params = new URLSearchParams(searchParams)
    if (val) params.set(key, val); else params.delete(key)
    setSearchParams(params)
    setPage(1)
  }

  const columns = useMemo(() => [
    col.accessor('object_name', {
      header: 'Name',
      cell: info => <span className="font-medium text-gray-900 text-sm">{info.getValue()}</span>,
    }),
    col.accessor('object_type', {
      header: 'Type',
      cell: info => <ObjectTypeChip type={info.getValue()} />,
    }),
    col.accessor(row => valueText(row), {
      id: 'value',
      header: 'Value / Details',
      cell: info => (
        <span className="text-gray-600 text-xs font-mono">{info.getValue() || '—'}</span>
      ),
    }),
    col.accessor(row => (row.members ? row.members.length : 0), {
      id: 'members',
      header: 'Members',
      cell: info => {
        const obj = info.row.original
        return obj.members && obj.members.length > 0
          ? <span className="text-gray-500 text-xs" title={obj.members.join(', ')}>{obj.members.length} members</span>
          : <span className="text-gray-500 text-xs">—</span>
      },
    }),
    col.accessor(row => row.comment || '', {
      id: 'comment',
      header: 'Comment',
      cell: info => (
        <span className="text-gray-400 text-xs max-w-[200px] truncate block">{info.getValue() || '—'}</span>
      ),
    }),
    col.display({
      id: 'status',
      header: 'Status',
      cell: info => <StatusBadges obj={info.row.original} />,
    }),
  ], [])

  const table = useReactTable({
    data: objects,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  const pageCount = Math.ceil(total / 100)

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Object Analysis</h1>
          <p className="page-subtitle">{total.toLocaleString()} objects · Identify unused, duplicate, or overlapping entries</p>
        </div>
      </div>
    <div className="page-body">
      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-5 p-3 bg-white rounded-xl border border-gray-100 shadow-sm">
        <select value={policyId} onChange={e => setFilter('policy_id', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white">
          <option value="">All Policies</option>
          {policies.map(p => (
            <option key={p.id} value={p.id}>
              {p.firewall_name}{!customerId && p.customer_name ? ` (${p.customer_name})` : ''}
            </option>
          ))}
        </select>

        <select value={objectType} onChange={e => setFilter('object_type', e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm bg-gray-50 focus:bg-white">
          <option value="">All Types</option>
          {['host', 'network', 'range', 'group', 'service', 'service-group', 'fqdn'].map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
            className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm w-56 bg-gray-50 focus:bg-white"
            placeholder="Search objects..." />
        </div>

        <div className="flex flex-wrap gap-1.5 items-center">
          {CATEGORIES.map(c => (
            <button
              key={c.value}
              onClick={() => { setFilter('category', category === c.value ? '' : c.value) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                category === c.value ? 'bg-orange-600 text-white border-orange-600' : 'border-gray-200 text-gray-600 hover:bg-gray-50'
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" /></div>
      ) : objects.length === 0 ? (
        <div className="card text-center py-12">
          <Package className="w-10 h-10 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500">No objects match the current filters.</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          <table className="data-table">
            <thead>
              {table.getHeaderGroups().map(hg => (
                <tr key={hg.id}>
                  {hg.headers.map(header => {
                    const canSort = header.column.getCanSort()
                    const sorted = header.column.getIsSorted()
                    return (
                      <th
                        key={header.id}
                        onClick={canSort ? header.column.getToggleSortingHandler() : undefined}
                        className={clsx(canSort && 'cursor-pointer select-none hover:text-blue-600')}
                        title={canSort ? 'Sort' : undefined}
                      >
                        <span className="flex items-center gap-1">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {canSort && (
                            sorted === 'asc' ? <ArrowUp className="w-3 h-3" />
                              : sorted === 'desc' ? <ArrowDown className="w-3 h-3" />
                              : <ArrowUpDown className="w-3 h-3 opacity-30" />
                          )}
                        </span>
                      </th>
                    )
                  })}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map(row => (
                <tr key={row.id} className={clsx('hover:bg-gray-50', row.original.is_unused && 'bg-orange-50')}>
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className="px-4 py-2.5">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>

          {pageCount > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 text-sm">
              <span className="text-gray-500">
                Page {page} of {pageCount} ({total} objects)
                <span className="text-gray-400 ml-2">· sorting applies to this page</span>
              </span>
              <div className="flex gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="btn-secondary py-1 px-3">Prev</button>
                <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} disabled={page === pageCount} className="btn-secondary py-1 px-3">Next</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>{/* end page-body */}
    </div>
  )
}
