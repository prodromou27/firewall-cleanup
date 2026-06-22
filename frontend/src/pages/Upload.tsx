import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import {
  AlertCircle, CheckCircle, ChevronRight, FileText, Loader, Plus, Search,
  ShieldAlert, Upload as UploadIcon, Users,
} from 'lucide-react'
import { getCustomers, getDevices, getPolicy, uploadPolicy } from '../api/client'
import { ErrorState } from '../components/ui/page-state'
import type { Customer, FirewallDeviceT, Policy } from '../types'

interface FormValues {
  customer_id: string
  vendor: string
  firewall_name: string
  policy_package: string
  notes: string
}

interface ImportQuality {
  rule_count?: number
  object_count?: number
  quality_score: number
  completeness_score: number
  incomplete_import?: boolean
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

interface UploadResult {
  warnings: string[]
  rules_parsed: number
  objects_parsed: number
  policy_id: string
  customer_id: string
  vendor?: string
  firewall_name?: string
  import_quality?: ImportQuality
  message?: string
}

type Phase = 'idle' | 'uploading' | 'parsing' | 'analysis' | 'completed' | 'failed'

const VENDORS = [
  { value: 'FortiGate', label: 'FortiGate' },
  { value: 'CheckPoint', label: 'Check Point' },
  { value: 'PaloAlto', label: 'Palo Alto Networks' },
  { value: 'CiscoASA', label: 'Cisco ASA' },
  { value: 'HuaweiUSG', label: 'Huawei USG' },
]

const FILE_HINT: Record<string, string> = {
  FortiGate: '.conf, .cfg, .txt, or .json FortiOS export',
  CheckPoint: '.json or .txt management API export',
  PaloAlto: '.xml or .json Panorama/device config export',
  CiscoASA: '.txt, .cfg, or .conf show running-config output',
  HuaweiUSG: '.txt, .cfg, or .conf display current-configuration output',
}

const FILE_ACCEPT: Record<string, string> = {
  FortiGate: '.conf,.txt,.json,.cfg',
  CheckPoint: '.json,.txt',
  PaloAlto: '.xml,.json',
  CiscoASA: '.txt,.conf,.cfg',
  HuaweiUSG: '.txt,.cfg,.conf',
}

export const ALLOWED_UPLOAD_EXTENSIONS: Record<string, string[]> = {
  FortiGate: ['.conf', '.txt', '.json', '.cfg'],
  CheckPoint: ['.json', '.txt'],
  PaloAlto: ['.xml', '.json'],
  CiscoASA: ['.txt', '.conf', '.cfg'],
  HuaweiUSG: ['.txt', '.cfg', '.conf'],
}

export function uploadFileExtension(name: string) {
  const i = name.lastIndexOf('.')
  return i >= 0 ? name.slice(i).toLowerCase() : ''
}

export function uploadDetailMessage(detail: unknown) {
  if (!detail) return 'Upload failed.'
  if (typeof detail === 'string') return detail
  if (typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message?: unknown }).message || 'Upload failed.')
  }
  return 'Upload failed.'
}

export function validateUploadFile(file: Pick<File, 'name' | 'size'> | null, vendor: string) {
  if (!file) return 'Please select a supported configuration file.'
  const allowed = ALLOWED_UPLOAD_EXTENSIONS[vendor] || []
  const ext = uploadFileExtension(file.name)
  if (!allowed.includes(ext)) {
    return `Unsupported file type ${ext || '(none)'} for ${vendor}. Supported: ${allowed.join(', ')}.`
  }
  if (file.size === 0) return 'The selected file is empty. Export the firewall configuration again and retry.'
  return null
}

function phaseLabel(phase: Phase) {
  switch (phase) {
    case 'uploading': return 'Uploading file'
    case 'parsing': return 'Parsing vendor configuration'
    case 'analysis': return 'Running findings analysis'
    case 'completed': return 'Analysis completed'
    case 'failed': return 'Analysis failed'
    default: return 'Ready to import'
  }
}

function QualityGauge({ score, label }: { score: number; label: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-600">{label}</span>
        <span className="text-xs font-bold text-gray-800">{score}/100</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-gray-100">
        <div
          className={`h-full rounded-full ${score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-amber-500' : 'bg-red-500'}`}
          style={{ width: `${Math.max(0, Math.min(100, score))}%` }}
        />
      </div>
    </div>
  )
}

function StatusPill({ ok, label, value }: { ok: boolean; label: string; value: string }) {
  return (
    <div className={`rounded-lg border p-3 ${ok ? 'border-green-200 bg-green-50 text-green-800' : 'border-amber-200 bg-amber-50 text-amber-800'}`}>
      <div className="text-xs font-semibold">{ok ? 'Available' : 'Missing'}: {label}</div>
      <div className="mt-0.5 text-sm font-bold">{value}</div>
    </div>
  )
}

export function Upload() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [customers, setCustomers] = useState<Customer[]>([])
  const [devices, setDevices] = useState<FirewallDeviceT[]>([])
  const [selectedDeviceId, setSelectedDeviceId] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [uploadProgress, setUploadProgress] = useState(0)
  const [result, setResult] = useState<UploadResult | null>(null)
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [error, setError] = useState<string | null>(null)

  const preselectedCustomer = searchParams.get('customer_id') || ''
  const { register, handleSubmit, formState: { errors }, watch, setValue } = useForm<FormValues>({
    defaultValues: {
      customer_id: preselectedCustomer,
      vendor: 'FortiGate',
      policy_package: 'Default',
      firewall_name: '',
      notes: '',
    },
  })

  const selectedCustomerId = watch('customer_id')
  const selectedVendor = watch('vendor')
  const selectedCustomer = customers.find(c => c.id === selectedCustomerId)
  const uploading = ['uploading', 'parsing', 'analysis'].includes(phase)

  useEffect(() => {
    getCustomers({ status: 'active' }).then(setCustomers).catch(() => setCustomers([]))
  }, [])

  useEffect(() => {
    setSelectedDeviceId('')
    setDevices([])
    if (!selectedCustomerId) return
    getDevices(selectedCustomerId)
      .then(rows => setDevices(rows))
      .catch(() => setDevices([]))
  }, [selectedCustomerId])

  useEffect(() => {
    if (!selectedDeviceId) return
    const d = devices.find(x => x.id === selectedDeviceId)
    if (!d) return
    setValue('vendor', d.vendor)
    setValue('firewall_name', d.name)
    if (d.cp_policy_package) setValue('policy_package', d.cp_policy_package)
  }, [selectedDeviceId, devices, setValue])

  useEffect(() => {
    if (!result?.policy_id || phase !== 'analysis') return
    let cancelled = false
    let tries = 0
    const poll = async () => {
      tries += 1
      try {
        const p = await getPolicy(result.policy_id)
        if (cancelled) return
        setPolicy(p)
        if (p.analysis_status === 'completed') {
          setPhase('completed')
        } else if (p.analysis_status === 'failed') {
          setPhase('failed')
          setError(p.analysis_error || 'Analysis failed after import. Review parser warnings and try re-running analysis.')
        } else if (tries < 90) {
          window.setTimeout(poll, 2000)
        }
      } catch {
        if (!cancelled && tries < 90) window.setTimeout(poll, 2500)
      }
    }
    poll()
    return () => { cancelled = true }
  }, [result?.policy_id, phase])

  const compatibleDevices = useMemo(
    () => devices.filter(d => !selectedVendor || d.vendor === selectedVendor),
    [devices, selectedVendor],
  )

  const validateFile = () => {
    if (!file) return 'Please select a supported configuration file.'
    return validateUploadFile(file, selectedVendor)
  }

  const onSubmit = async (values: FormValues) => {
    const validation = validateFile()
    if (validation) { setError(validation); return }

    setPhase('uploading')
    setUploadProgress(0)
    setError(null)
    setResult(null)
    setPolicy(null)

    const fd = new FormData()
    Object.entries(values).forEach(([k, v]) => fd.append(k, v || ''))
    fd.append('file', file as File)

    try {
      const res = await uploadPolicy(fd, event => {
        if (!event.total) return
        const pct = Math.round((event.loaded / event.total) * 100)
        setUploadProgress(pct)
        if (pct >= 100) setPhase('parsing')
      })
      setResult(res)
      setPhase('analysis')
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
      setPhase('failed')
      setError(uploadDetailMessage(detail))
    }
  }

  const reset = () => {
    setFile(null)
    setResult(null)
    setPolicy(null)
    setError(null)
    setPhase('idle')
    setUploadProgress(0)
    if (fileRef.current) fileRef.current.value = ''
  }

  const findingsUrl = result ? `/findings?customer_id=${result.customer_id}&policy_id=${result.policy_id}` : '/findings'
  const quality = result?.import_quality
  const warnings = result?.warnings || []

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Upload Policy</h1>
          <p className="page-subtitle">Import offline firewall exports for read-only PolicyInsight analysis.</p>
        </div>
      </div>

      <div className="page-body grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
          <div className="card">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="font-semibold text-gray-800">Customer</h2>
              <Link to="/customers" className="inline-flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800">
                <Users className="h-3 w-3" /> Manage customers
              </Link>
            </div>
            {customers.length === 0 ? (
              <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm">
                <p className="mb-2 font-medium text-amber-800">No active customers are available.</p>
                <Link to="/customers" className="btn-primary w-fit text-sm"><Plus className="h-3.5 w-3.5" /> Onboard customer</Link>
              </div>
            ) : (
              <>
                <label htmlFor="upload-customer" className="sr-only">Customer</label>
                <select id="upload-customer" {...register('customer_id', { required: 'Please select a customer' })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm">
                  <option value="">Select customer</option>
                  {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                {errors.customer_id && <p className="mt-1 text-xs text-red-600">{errors.customer_id.message}</p>}
                {selectedCustomer && (
                  <div className="mt-2 rounded-lg bg-blue-50 px-3 py-2 text-xs text-gray-600">
                    {selectedCustomer.total_policies} existing policies, {selectedCustomer.total_findings} findings
                    {selectedCustomer.contact_name ? `, contact: ${selectedCustomer.contact_name}` : ''}
                  </div>
                )}
              </>
            )}
          </div>

          <div className="card space-y-4">
            <h2 className="font-semibold text-gray-800">Firewall and Vendor</h2>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="upload-vendor" className="mb-1.5 block text-xs font-semibold text-gray-600">Vendor *</label>
                <select id="upload-vendor" {...register('vendor', { required: true })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm">
                  {VENDORS.map(v => <option key={v.value} value={v.value}>{v.label}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="upload-device" className="mb-1.5 block text-xs font-semibold text-gray-600">Existing firewall</label>
                <select
                  id="upload-device"
                  value={selectedDeviceId}
                  onChange={e => setSelectedDeviceId(e.target.value)}
                  disabled={!selectedCustomerId || devices.length === 0}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm disabled:bg-gray-50 disabled:text-gray-400"
                >
                  <option value="">Manual firewall name</option>
                  {compatibleDevices.map(d => (
                    <option key={d.id} value={d.id}>{d.name} ({d.host})</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="upload-firewall-name" className="mb-1.5 block text-xs font-semibold text-gray-600">Firewall name *</label>
                <input
                  id="upload-firewall-name"
                  {...register('firewall_name', { required: 'Firewall name is required' })}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
                  placeholder="e.g. FGT-HQ-01"
                />
                {errors.firewall_name && <p className="mt-1 text-xs text-red-600">{errors.firewall_name.message}</p>}
              </div>
              <div>
                <label htmlFor="upload-policy-package" className="mb-1.5 block text-xs font-semibold text-gray-600">Policy package</label>
                <input id="upload-policy-package" {...register('policy_package')} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm" placeholder="Default" />
              </div>
            </div>
            <div>
              <label htmlFor="upload-notes" className="mb-1.5 block text-xs font-semibold text-gray-600">Notes</label>
              <textarea id="upload-notes" {...register('notes')} rows={2} className="w-full resize-none rounded-lg border border-gray-300 px-3 py-2 text-sm" placeholder="Scope notes, export source, or customer context" />
            </div>
          </div>

          <div className="card">
            <h2 className="mb-4 font-semibold text-gray-800">Configuration File</h2>
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              className={`w-full rounded-xl border-2 border-dashed p-8 text-center transition ${file ? 'border-blue-400 bg-blue-50' : 'border-gray-300 hover:border-blue-400 hover:bg-blue-50'}`}
            >
              <UploadIcon className="mx-auto mb-3 h-10 w-10 text-gray-400" />
              {file ? (
                <span className="inline-flex items-center gap-2 text-sm font-medium text-blue-700">
                  <FileText className="h-4 w-4" /> {file.name}
                  <span className="text-xs font-normal text-gray-500">({(file.size / 1024).toFixed(0)} KB)</span>
                </span>
              ) : (
                <>
                  <span className="block text-sm font-medium text-gray-700">Select firewall export</span>
                  <span className="mt-1 block text-xs text-gray-500">{FILE_HINT[selectedVendor]}</span>
                </>
              )}
            </button>
            <input
              ref={fileRef}
              type="file"
              className="hidden"
              accept={FILE_ACCEPT[selectedVendor] || '.conf,.txt,.json,.xml,.cfg'}
              onChange={e => {
                setFile(e.target.files?.[0] || null)
                setError(null)
              }}
            />
            {file && validateFile() && <p className="mt-2 text-xs font-medium text-red-600">{validateFile()}</p>}
          </div>

          {error && <ErrorState title={phase === 'failed' ? 'Import failed' : 'Upload issue'} message={error} />}

          <button disabled={uploading || !file || customers.length === 0} className="btn-primary w-full justify-center py-2.5 disabled:opacity-50">
            {uploading ? <><Loader className="h-4 w-4 animate-spin" /> {phaseLabel(phase)}</> : <><UploadIcon className="h-4 w-4" /> Upload and analyze</>}
          </button>
        </form>

        <aside className="space-y-4">
          <div className="card">
            <h3 className="mb-3 font-semibold text-gray-800">Import Progress</h3>
            <div className="space-y-3">
              {(['uploading', 'parsing', 'analysis', 'completed'] as Phase[]).map((p, idx) => {
                const order = ['idle', 'uploading', 'parsing', 'analysis', 'completed']
                const done = order.indexOf(phase) > order.indexOf(p) || phase === 'completed'
                const active = phase === p
                return (
                  <div key={p} className="flex items-center gap-3">
                    <span className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${done ? 'bg-green-100 text-green-700' : active ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-400'}`}>
                      {done ? <CheckCircle className="h-4 w-4" /> : idx + 1}
                    </span>
                    <span className={`text-sm ${active ? 'font-semibold text-blue-700' : done ? 'text-gray-700' : 'text-gray-400'}`}>{phaseLabel(p)}</span>
                  </div>
                )
              })}
            </div>
            {phase === 'uploading' && (
              <div className="mt-4">
                <div className="mb-1 flex justify-between text-xs text-gray-500"><span>Upload</span><span>{uploadProgress}%</span></div>
                <div className="h-2 overflow-hidden rounded-full bg-gray-100"><div className="h-full bg-blue-600" style={{ width: `${uploadProgress}%` }} /></div>
              </div>
            )}
            {policy && (
              <div className="mt-4 rounded-lg bg-gray-50 px-3 py-2 text-xs text-gray-600">
                Current analysis status: <strong>{policy.analysis_status}</strong>
              </div>
            )}
          </div>

          {result && (
            <div className="card space-y-4">
              <div className="flex items-start gap-3">
                <CheckCircle className="mt-0.5 h-5 w-5 text-green-600" />
                <div>
                  <h3 className="font-semibold text-gray-800">Import created</h3>
                  <p className="text-sm text-gray-600">
                    Parsed {result.rules_parsed.toLocaleString()} rules and {result.objects_parsed.toLocaleString()} objects.
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="rounded-lg border bg-white p-2"><div className="text-lg font-bold text-blue-700">{result.rules_parsed}</div><div className="text-[11px] text-gray-500">Rules</div></div>
                <div className="rounded-lg border bg-white p-2"><div className="text-lg font-bold text-purple-700">{result.objects_parsed}</div><div className="text-[11px] text-gray-500">Objects</div></div>
                <div className="rounded-lg border bg-white p-2"><div className="text-lg font-bold text-amber-700">{warnings.length}</div><div className="text-[11px] text-gray-500">Warnings</div></div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button onClick={() => navigate(findingsUrl)} disabled={phase !== 'completed'} className="btn-primary text-sm disabled:opacity-50">
                  <Search className="h-4 w-4" /> View Findings <ChevronRight className="h-4 w-4" />
                </button>
                <button onClick={() => navigate(`/policies/${result.policy_id}/rules`)} className="btn-secondary text-sm">View Rulebase</button>
                <button onClick={reset} className="btn-secondary text-sm">Upload Another</button>
              </div>
            </div>
          )}

          {quality && (
            <div className={`card ${quality.quality_score >= 80 ? 'border-green-200' : quality.quality_score >= 50 ? 'border-amber-200' : 'border-red-200'}`}>
              <div className="mb-3 flex items-center justify-between">
                <h3 className="flex items-center gap-2 font-semibold text-gray-800"><ShieldAlert className="h-4 w-4 text-blue-600" /> Import Quality</h3>
                <span className={`rounded-full px-2 py-0.5 text-xs font-bold ${quality.quality_score >= 80 ? 'bg-green-100 text-green-700' : quality.quality_score >= 50 ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-700'}`}>
                  {quality.quality_score >= 80 ? 'Good' : quality.quality_score >= 50 ? 'Limited' : 'Needs review'}
                </span>
              </div>
              <div className="space-y-3">
                <QualityGauge score={quality.quality_score} label="Analysis quality" />
                <QualityGauge score={quality.completeness_score} label="Data completeness" />
                <StatusPill ok={quality.object_count !== 0 && result.objects_parsed > 0} label="Objects and groups" value={`${result.objects_parsed} imported`} />
                <StatusPill ok={quality.has_hit_counts} label="Hit-count data" value={`${quality.rules_with_hit_count} rules`} />
                <StatusPill ok={quality.has_last_hit} label="Last-hit timestamps" value={`${quality.rules_with_last_hit} rules`} />
              </div>
              {quality.confidence_note && <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">{quality.confidence_note}</div>}
              {quality.data_gaps.length > 0 && (
                <div className="mt-3">
                  <p className="mb-1.5 text-xs font-semibold text-gray-600">Incomplete import signals</p>
                  <ul className="space-y-1 text-xs text-gray-600">
                    {quality.data_gaps.map((gap, i) => <li key={i} className="flex gap-1.5"><span className="text-amber-500">-</span><span>{gap}</span></li>)}
                  </ul>
                </div>
              )}
            </div>
          )}

          {warnings.length > 0 && (
            <div className="card border-amber-200 bg-amber-50">
              <h3 className="mb-2 flex items-center gap-2 font-semibold text-amber-800"><AlertCircle className="h-4 w-4" /> Parser Warnings</h3>
              <ul className="max-h-64 space-y-1 overflow-y-auto text-sm text-amber-800">
                {warnings.map((w, i) => <li key={i}>- {w}</li>)}
              </ul>
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}
