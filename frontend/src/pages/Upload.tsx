import { useState, useRef, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { Upload as UploadIcon, FileText, AlertCircle, CheckCircle, Loader, Plus, Users, ShieldAlert } from 'lucide-react'
import { uploadPolicy, getCustomers } from '../api/client'
import type { Customer } from '../types'

interface FormValues {
  customer_id: string
  vendor: string
  firewall_name: string
  policy_package: string
  notes: string
}

interface ImportQuality {
  quality_score: number
  completeness_score: number
  has_hit_counts: boolean
  has_last_hit: boolean
  has_comments: boolean
  rules_with_hit_count: number
  rules_with_last_hit: number
  rules_with_comments: number
  warning_count: number
  data_gaps: string[]
  confidence_note: string | null
}

function QualityGauge({ score, label, color }: { score: number; label: string; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs font-semibold text-gray-600">{label}</span>
          <span className={`text-xs font-bold ${color}`}>{score}/100</span>
        </div>
        <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
            style={{ width: `${score}%` }}
          />
        </div>
      </div>
    </div>
  )
}

export function Upload() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<{
    warnings: string[]; rules_parsed: number; objects_parsed: number
    policy_id: string; customer_id: string; vendor?: string; firewall_name?: string
    import_quality?: ImportQuality
  } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [customers, setCustomers] = useState<Customer[]>([])
  const fileRef = useRef<HTMLInputElement>(null)

  const preselectedCustomer = searchParams.get('customer_id') || ''

  const { register, handleSubmit, formState: { errors }, watch } = useForm<FormValues>({
    defaultValues: {
      customer_id: preselectedCustomer,
      vendor: 'FortiGate',
      policy_package: 'Default',
    },
  })

  useEffect(() => {
    getCustomers({ status: 'active' }).then(setCustomers)
  }, [])

  const onSubmit = async (values: FormValues) => {
    if (!file) { setError('Please select a file.'); return }
    setUploading(true)
    setError(null)
    setResult(null)

    const fd = new FormData()
    Object.entries(values).forEach(([k, v]) => fd.append(k, v))
    fd.append('file', file)

    try {
      const res = await uploadPolicy(fd)
      setResult(res)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Upload failed.'
      setError(msg)
    } finally {
      setUploading(false)
    }
  }

  const selectedCustomerId = watch('customer_id')
  const selectedVendor = watch('vendor')
  const selectedCustomer = customers.find(c => c.id === selectedCustomerId)
  const isCheckPoint = selectedVendor === 'CheckPoint'

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Upload Policy</h1>
          <p className="page-subtitle">Import a FortiGate or Check Point policy export for analysis</p>
        </div>
      </div>
    <div className="page-body max-w-2xl">

      {result ? (
        <div className="space-y-4">
          <div className="bg-green-50 border border-green-200 rounded-xl p-5">
            <div className="flex items-center gap-3 mb-3">
              <CheckCircle className="w-6 h-6 text-green-600" />
              <div>
                <h3 className="font-semibold text-green-800">Upload Successful</h3>
                <p className="text-green-700 text-sm">
                  Parsed <strong>{result.rules_parsed}</strong> rules and{' '}
                  <strong>{result.objects_parsed}</strong> objects.
                  Analysis is running in the background.
                </p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="bg-white rounded-lg p-2 border border-green-100">
                <p className="text-2xl font-extrabold text-blue-700">{result.rules_parsed}</p>
                <p className="text-xs text-gray-500 font-medium">Rules</p>
              </div>
              <div className="bg-white rounded-lg p-2 border border-green-100">
                <p className="text-2xl font-extrabold text-purple-700">{result.objects_parsed}</p>
                <p className="text-xs text-gray-500 font-medium">Objects</p>
              </div>
              <div className="bg-white rounded-lg p-2 border border-green-100">
                <p className="text-2xl font-extrabold text-orange-600">{result.warnings.length}</p>
                <p className="text-xs text-gray-500 font-medium">Warnings</p>
              </div>
            </div>
          </div>

          {/* Import Quality Panel */}
          {result.import_quality && (
            <div className={`border rounded-xl p-5 ${
              result.import_quality.quality_score >= 80 ? 'bg-green-50 border-green-200' :
              result.import_quality.quality_score >= 50 ? 'bg-yellow-50 border-yellow-200' :
              'bg-red-50 border-red-200'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <h4 className="font-semibold text-gray-800 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-blue-600" />
                  Import Quality Report
                </h4>
                <span className={`text-sm font-bold px-2 py-0.5 rounded-full ${
                  result.import_quality.quality_score >= 80 ? 'bg-green-200 text-green-800' :
                  result.import_quality.quality_score >= 50 ? 'bg-yellow-200 text-yellow-800' :
                  'bg-red-200 text-red-800'
                }`}>
                  {result.import_quality.quality_score >= 80 ? '✓ Good' :
                   result.import_quality.quality_score >= 50 ? '⚠ Moderate' : '✗ Limited'}
                </span>
              </div>

              <div className="space-y-2 mb-4">
                <QualityGauge
                  score={result.import_quality.quality_score}
                  label="Analysis Quality"
                  color={result.import_quality.quality_score >= 80 ? 'text-green-700' : result.import_quality.quality_score >= 50 ? 'text-yellow-700' : 'text-red-700'}
                />
                <QualityGauge
                  score={result.import_quality.completeness_score}
                  label="Data Completeness"
                  color="text-blue-700"
                />
              </div>

              <div className="grid grid-cols-3 gap-2 mb-4 text-center text-xs">
                <div className={`rounded-lg p-2 ${result.import_quality.has_hit_counts ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-500'}`}>
                  {result.import_quality.has_hit_counts ? '✓' : '✗'} Hit Counts<br/>
                  <span className="font-bold">{result.import_quality.rules_with_hit_count}</span> rules
                </div>
                <div className={`rounded-lg p-2 ${result.import_quality.has_last_hit ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-500'}`}>
                  {result.import_quality.has_last_hit ? '✓' : '✗'} Last-Hit Data<br/>
                  <span className="font-bold">{result.import_quality.rules_with_last_hit}</span> rules
                </div>
                <div className={`rounded-lg p-2 ${result.import_quality.has_comments ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-500'}`}>
                  {result.import_quality.has_comments ? '✓' : '✗'} Rule Comments<br/>
                  <span className="font-bold">{result.import_quality.rules_with_comments}</span> rules
                </div>
              </div>

              {result.import_quality.confidence_note && (
                <div className="bg-amber-100 border border-amber-300 rounded-lg px-3 py-2 text-xs text-amber-800 font-medium mb-3">
                  ⚠️ {result.import_quality.confidence_note}
                </div>
              )}

              {result.import_quality.data_gaps.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-600 mb-1.5">Data Gaps Detected:</p>
                  <ul className="text-xs text-gray-600 space-y-1">
                    {result.import_quality.data_gaps.map((gap, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-orange-500 flex-shrink-0 mt-0.5">•</span>
                        {gap}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {result.warnings.length > 0 && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
              <h4 className="font-semibold text-yellow-800 mb-2 flex items-center gap-2 text-sm">
                <AlertCircle className="w-4 h-4" /> Parsing Warnings ({result.warnings.length})
              </h4>
              <ul className="text-sm text-yellow-700 space-y-1">
                {result.warnings.map((w, i) => <li key={i}>• {w}</li>)}
              </ul>
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => navigate(`/customers/${result.customer_id}`)}
              className="btn-primary"
            >
              View Customer Dashboard
            </button>
            <button
              onClick={() => navigate(`/policies/${result.policy_id}/rules`)}
              className="btn-secondary"
            >
              View Rulebase
            </button>
            <button onClick={() => { setResult(null); setFile(null) }} className="btn-secondary">
              Upload Another
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
          {/* Customer select */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-gray-800">Customer</h2>
              <Link to="/customers" className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1">
                <Users className="w-3 h-3" /> Manage customers
              </Link>
            </div>

            {customers.length === 0 ? (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-sm">
                <p className="text-yellow-800 font-medium mb-2">No customers onboarded yet.</p>
                <Link to="/customers" className="btn-primary text-sm flex items-center gap-2 w-fit">
                  <Plus className="w-3.5 h-3.5" /> Onboard a Customer First
                </Link>
              </div>
            ) : (
              <div>
                <select
                  {...register('customer_id', { required: 'Please select a customer' })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">— Select customer —</option>
                  {customers.map(c => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                  ))}
                </select>
                {errors.customer_id && <p className="text-red-500 text-xs mt-1">{errors.customer_id.message}</p>}

                {selectedCustomer && (
                  <div className="mt-2 text-xs text-gray-500 bg-blue-50 rounded-lg px-3 py-2">
                    {selectedCustomer.total_policies} existing {selectedCustomer.total_policies === 1 ? 'policy' : 'policies'} ·{' '}
                    {selectedCustomer.total_findings} findings
                    {selectedCustomer.contact_name && ` · Contact: ${selectedCustomer.contact_name}`}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Firewall details */}
          <div className="card space-y-4">
            <h2 className="font-semibold text-gray-800">Firewall Details</h2>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Vendor *</label>
                <select
                  {...register('vendor', { required: true })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="FortiGate">FortiGate</option>
                  <option value="CheckPoint">Check Point</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Policy Package</label>
                <input
                  {...register('policy_package')}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. Standard Policy"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Firewall Name *</label>
              <input
                {...register('firewall_name', { required: 'Required' })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="e.g. FGT-HQ-01 or CP-GW-PROD"
              />
              {errors.firewall_name && <p className="text-red-500 text-xs mt-1">{errors.firewall_name.message}</p>}
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Notes</label>
              <textarea
                {...register('notes')}
                rows={2}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                placeholder="Any notes about this policy export or analysis scope…"
              />
            </div>
          </div>

          {/* File upload */}
          <div className="card">
            <h2 className="font-semibold text-gray-800 mb-4">Policy File</h2>
            <div
              onClick={() => fileRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all
                ${file ? 'border-blue-400 bg-blue-50' : 'border-gray-300 hover:border-blue-400 hover:bg-blue-50'}`}
            >
              <UploadIcon className="w-10 h-10 text-gray-400 mx-auto mb-3" />
              {file ? (
                <div className="flex items-center justify-center gap-2 text-blue-700">
                  <FileText className="w-4 h-4" />
                  <span className="font-medium text-sm">{file.name}</span>
                  <span className="text-gray-400 text-xs">({(file.size / 1024).toFixed(0)} KB)</span>
                </div>
              ) : (
                <>
                  <p className="text-sm font-medium text-gray-600">Click to select file</p>
                  <p className="text-xs text-gray-400 mt-1">
                    {isCheckPoint
                      ? <>Check Point: <code>.csv</code> (policy export from SmartConsole)</>
                      : <>FortiGate: <code>.conf</code> or <code>.json</code></>}
                  </p>
                </>
              )}
              <input
                ref={fileRef} type="file" className="hidden"
                accept={isCheckPoint ? '.csv' : '.conf,.txt,.json'}
                onChange={e => setFile(e.target.files?.[0] || null)}
              />
            </div>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={uploading || !file || customers.length === 0}
            className="btn-primary w-full flex items-center justify-center gap-2 py-2.5"
          >
            {uploading ? (
              <><Loader className="w-4 h-4 animate-spin" /> Uploading & Analysing…</>
            ) : (
              <><UploadIcon className="w-4 h-4" /> Upload & Analyse</>
            )}
          </button>
        </form>
      )}
    </div>{/* end page-body */}
    </div>
  )
}
