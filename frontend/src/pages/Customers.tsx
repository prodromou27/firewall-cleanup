import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import {
  Users, Plus, Search, Trash2, Eye, Edit2, X,
  Building2, Mail, Tag, AlertTriangle, CheckCircle, Clock
} from 'lucide-react'
import { getCustomers, createCustomer, updateCustomer, deleteCustomer } from '../api/client'
import type { Customer } from '../types'
import { clsx } from 'clsx'

// ── Risk indicator ──────────────────────────────────────────
function RiskPill({ high, total }: { high: number; total: number }) {
  if (total === 0) return <span className="text-xs text-gray-400">No findings</span>
  if (high > 0) return (
    <span className="flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 px-2 py-0.5 rounded-full">
      <AlertTriangle className="w-3 h-3" />{high} High
    </span>
  )
  return (
    <span className="flex items-center gap-1 text-xs font-semibold text-yellow-700 bg-yellow-50 px-2 py-0.5 rounded-full">
      {total} findings
    </span>
  )
}

// ── Customer form ───────────────────────────────────────────
interface FormValues {
  name: string
  description: string
  contact_name: string
  contact_email: string
  industry: string
  tags: string
  notes: string
}

const INDUSTRIES = [
  'Financial Services', 'Healthcare', 'Government', 'Retail',
  'Manufacturing', 'Technology', 'Education', 'Energy', 'Other',
]

function CustomerModal({
  customer,
  onClose,
  onSaved,
}: {
  customer?: Customer
  onClose: () => void
  onSaved: () => void
}) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({
    defaultValues: {
      name: customer?.name || '',
      description: customer?.description || '',
      contact_name: customer?.contact_name || '',
      contact_email: customer?.contact_email || '',
      industry: customer?.industry || '',
      tags: customer?.tags || '',
      notes: customer?.notes || '',
    },
  })

  const onSubmit = async (values: FormValues) => {
    setSaving(true)
    setError('')
    try {
      if (customer) {
        await updateCustomer(customer.id, values as unknown as Record<string, string>)
      } else {
        await createCustomer(values as unknown as Record<string, string>)
      }
      onSaved()
      onClose()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        || 'Failed to save customer.'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 bg-[#0f2744]">
          <h2 className="text-white font-semibold">
            {customer ? 'Edit Customer' : 'Onboard New Customer'}
          </h2>
          <button onClick={onClose} className="text-blue-300 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Customer Name *</label>
              <input
                {...register('name', { required: 'Name is required' })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. Acme Corporation"
              />
              {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name.message}</p>}
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Description</label>
              <input
                {...register('description')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Brief description of this customer or engagement"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Contact Name</label>
              <input
                {...register('contact_name')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="John Smith"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Contact Email</label>
              <input
                {...register('contact_email')}
                type="email"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="john@acme.com"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Industry</label>
              <select
                {...register('industry')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select industry</option>
                {INDUSTRIES.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Tags</label>
              <input
                {...register('tags')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. production, audit-2026"
              />
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Internal Notes</label>
              <textarea
                {...register('notes')}
                rows={2}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                placeholder="Any notes about this engagement..."
              />
            </div>
          </div>

          {error && (
            <p className="text-red-600 text-sm bg-red-50 rounded-lg px-3 py-2">{error}</p>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary">
              {saving ? 'Saving…' : customer ? 'Save Changes' : 'Create Customer'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Customer card ───────────────────────────────────────────
function CustomerCard({ customer, onEdit, onDelete, onView }: {
  customer: Customer
  onEdit: () => void
  onDelete: () => void
  onView: () => void
}) {
  const tags = customer.tags?.split(',').map(t => t.trim()).filter(Boolean) || []

  return (
    <div
      className="bg-white rounded-xl border border-gray-200 shadow-sm hover:shadow-md hover:border-blue-200 transition-all cursor-pointer group"
      onClick={onView}
    >
      <div className="p-5">
        {/* Top row */}
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center flex-shrink-0 shadow-sm">
              <span className="text-white font-bold text-sm">
                {customer.name.slice(0, 2).toUpperCase()}
              </span>
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 group-hover:text-blue-700 transition-colors">
                {customer.name}
              </h3>
              {customer.industry && (
                <p className="text-xs text-gray-400">{customer.industry}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
            <button onClick={onEdit} className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-blue-600">
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            <button onClick={onDelete} className="p-1.5 hover:bg-red-50 rounded-lg text-gray-400 hover:text-red-600">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {customer.description && (
          <p className="text-xs text-gray-500 mb-3 line-clamp-2">{customer.description}</p>
        )}

        {/* Stats */}
        <div className="grid grid-cols-3 gap-2 mb-3">
          <div className="text-center bg-gray-50 rounded-lg py-2">
            <p className="text-lg font-bold text-gray-800">{customer.total_policies}</p>
            <p className="text-[10px] text-gray-400 font-medium">Policies</p>
          </div>
          <div className="text-center bg-gray-50 rounded-lg py-2">
            <p className="text-lg font-bold text-gray-800">{customer.total_rules}</p>
            <p className="text-[10px] text-gray-400 font-medium">Rules</p>
          </div>
          <div className={clsx('text-center rounded-lg py-2', customer.high_findings > 0 ? 'bg-red-50' : 'bg-gray-50')}>
            <p className={clsx('text-lg font-bold', customer.high_findings > 0 ? 'text-red-600' : 'text-gray-800')}>
              {customer.total_findings}
            </p>
            <p className="text-[10px] text-gray-400 font-medium">Findings</p>
          </div>
        </div>

        {/* Risk + contact */}
        <div className="flex items-center justify-between">
          <RiskPill high={customer.high_findings} total={customer.total_findings} />
          {customer.contact_name && (
            <span className="text-xs text-gray-400 truncate max-w-[120px]">{customer.contact_name}</span>
          )}
        </div>

        {/* Tags */}
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2.5">
            {tags.slice(0, 3).map(tag => (
              <span key={tag} className="text-[10px] bg-blue-50 text-blue-600 px-1.5 py-0.5 rounded font-medium">
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-5 py-2.5 border-t border-gray-100 flex items-center justify-between">
        <span className={clsx(
          'text-[10px] font-semibold uppercase tracking-wide',
          customer.status === 'active' ? 'text-green-600' : 'text-gray-400'
        )}>
          {customer.status}
        </span>
        <span className="text-xs text-gray-400">
          {customer.created_at ? new Date(customer.created_at).toLocaleDateString() : ''}
        </span>
      </div>
    </div>
  )
}

// ── Inline delete-confirm dialog ─────────────────────────────
function DeleteConfirmDialog({
  customer,
  onConfirm,
  onCancel,
}: { customer: Customer; onConfirm: () => void; onCancel: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl p-6 max-w-sm w-full mx-4 border border-gray-200">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-full bg-red-100">
            <AlertTriangle className="w-5 h-5 text-red-600" />
          </div>
          <h3 className="text-base font-semibold text-gray-900">Delete customer?</h3>
        </div>
        <p className="text-sm text-gray-600 mb-1">
          <span className="font-semibold">{customer.name}</span> will be permanently removed, including all
          associated policies and findings.
        </p>
        <p className="text-xs text-red-600 font-medium mb-5">This action cannot be undone.</p>
        <div className="flex gap-3 justify-end">
          <button onClick={onCancel} className="px-4 py-2 text-sm rounded-lg border border-gray-300 hover:bg-gray-50 transition-colors">Cancel</button>
          <button onClick={onConfirm} className="px-4 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-700 font-semibold transition-colors">Delete</button>
        </div>
      </div>
    </div>
  )
}

// ── Main Customers page ─────────────────────────────────────
export function Customers() {
  const navigate = useNavigate()
  const [customers, setCustomers] = useState<Customer[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingCustomer, setEditingCustomer] = useState<Customer | undefined>()
  const [pendingDelete, setPendingDelete] = useState<Customer | undefined>()

  const load = useCallback(() => {
    setLoading(true)
    getCustomers().then(setCustomers).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const handleDelete = (c: Customer) => setPendingDelete(c)

  const confirmDelete = async () => {
    if (!pendingDelete) return
    await deleteCustomer(pendingDelete.id)
    setPendingDelete(undefined)
    load()
  }

  const filtered = customers.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    (c.description || '').toLowerCase().includes(search.toLowerCase())
  )

  const activeCount = customers.filter(c => c.status === 'active').length
  const totalFindings = customers.reduce((a, c) => a + c.total_findings, 0)
  const highRiskCount = customers.filter(c => c.high_findings > 0).length

  return (
    <div>
      {pendingDelete && (
        <DeleteConfirmDialog
          customer={pendingDelete}
          onConfirm={confirmDelete}
          onCancel={() => setPendingDelete(undefined)}
        />
      )}
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Customers</h1>
          <p className="page-subtitle">
            {activeCount} active · {totalFindings} findings · {highRiskCount} with high risk
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 pr-3 py-2 border border-gray-200 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 w-56"
              placeholder="Search customers…"
            />
          </div>
          <button onClick={() => { setEditingCustomer(undefined); setShowModal(true) }} className="btn-primary">
            <Plus className="w-4 h-4" /> Onboard Customer
          </button>
        </div>
      </div>
    <div className="page-body">

      {loading ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20">
          <div className="w-16 h-16 rounded-2xl bg-blue-50 flex items-center justify-center mx-auto mb-4">
            <Users className="w-8 h-8 text-blue-400" />
          </div>
          <h2 className="text-lg font-semibold text-gray-700 mb-1">
            {customers.length === 0 ? 'No customers yet' : 'No results'}
          </h2>
          <p className="text-gray-400 text-sm mb-6">
            {customers.length === 0
              ? 'Onboard your first customer to get started.'
              : 'Try a different search term.'}
          </p>
          {customers.length === 0 && (
            <button onClick={() => { setEditingCustomer(undefined); setShowModal(true) }} className="btn-primary">
              Onboard First Customer
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {filtered.map(c => (
            <CustomerCard
              key={c.id}
              customer={c}
              onView={() => navigate(`/customers/${c.id}`)}
              onEdit={() => { setEditingCustomer(c); setShowModal(true) }}
              onDelete={() => handleDelete(c)}
            />
          ))}
        </div>
      )}

      {showModal && (
        <CustomerModal
          customer={editingCustomer}
          onClose={() => setShowModal(false)}
          onSaved={load}
        />
      )}
    </div>{/* end page-body */}
    </div>
  )
}
