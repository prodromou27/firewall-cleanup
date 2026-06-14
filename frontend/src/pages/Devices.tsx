import { useEffect, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  Server, Plus, Trash2, RefreshCw, CheckCircle2, XCircle,
  AlertCircle, Clock, Wifi, WifiOff, Settings, X, Eye, EyeOff,
  Activity, History, Network, Cpu, MapPin, Shield, Info,
  ChevronRight, Globe,
} from 'lucide-react'
import {
  getDevices, createDevice, updateDevice, deleteDevice,
  testDevice, syncDevice, getDeviceSyncStatus, resetDeviceSync
} from '../api/client'
import type { FirewallDeviceT } from '../types'
import { clsx } from 'clsx'
import { useForm } from 'react-hook-form'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '../components/ui/dialog'

// ── Status chip ─────────────────────────────────────────────────────────────
function SyncStatusChip({ status }: { status: string }) {
  const cfg: Record<string, { cls: string; icon: React.ReactNode; label: string }> = {
    never:   { cls: 'bg-gray-100 text-gray-500',   icon: <Clock className="w-3 h-3" />,       label: 'Never synced' },
    running: { cls: 'bg-blue-100 text-blue-700',   icon: <RefreshCw className="w-3 h-3 animate-spin" />, label: 'Syncing…' },
    ok:      { cls: 'bg-green-100 text-green-700', icon: <CheckCircle2 className="w-3 h-3" />, label: 'Synced' },
    error:   { cls: 'bg-red-100 text-red-700',     icon: <XCircle className="w-3 h-3" />,      label: 'Error' },
  }
  const c = cfg[status] || cfg.never
  return (
    <span className={clsx('inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full', c.cls)}>
      {c.icon} {c.label}
    </span>
  )
}

// ── Device form modal ─────────────────────────────────────────────────────
interface FormValues {
  name: string; vendor: string; host: string; port: string
  api_token: string; username: string; password: string
  use_ssl: boolean; verify_ssl: boolean; vdom: string
  cp_domain: string; cp_policy_package: string; cp_management_type: string
  sync_interval_hours: string  // empty string = disabled
}

interface TestPhase {
  phase: string
  ok: boolean
  detail: string
}

interface TestInfo {
  // FortiGate
  version?: string; serial?: string; hostname?: string
  vdoms?: string[]; rule_count?: number; interface_count?: number
  // CheckPoint
  api_server_version?: string; is_mds?: boolean; management_type?: string
  domains?: { name: string; uid: string }[]
  packages?: { name: string; access_layers: string[] }[]
  gateways?: { name: string; type: string; version?: string }[]
  // Palo Alto
  model?: string; sw_version?: string; vsys_list?: string[]
  object_count?: number; app_count?: number
  // Cisco ASA
  software_version?: string; interfaces?: { name: string; ip: string }[]
  // Huawei USG (also used by some vendors)
  zone_count?: number
}

function DeviceModal({
  customerId,
  device,
  onClose,
  onSaved,
}: {
  customerId: string
  device?: FirewallDeviceT
  onClose: () => void
  onSaved: () => void
}) {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testSuccess, setTestSuccess] = useState<boolean | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [testHint, setTestHint] = useState<string | null>(null)
  const [testPhases, setTestPhases] = useState<TestPhase[]>([])
  const [testInfo, setTestInfo] = useState<TestInfo | null>(null)

  const { register, handleSubmit, watch, formState: { errors } } = useForm<FormValues>({
    defaultValues: {
      name:                device?.name || '',
      vendor:              device?.vendor || 'FortiGate',
      host:                device?.host || '',
      port:                device?.port?.toString() || '',
      api_token:           '',
      username:            '',  // never pre-filled — API does not return plaintext username
      password:            '',
      use_ssl:             device?.use_ssl ?? true,
      verify_ssl:          device?.verify_ssl ?? false,
      vdom:                device?.vdom || 'root',
      cp_domain:           device?.cp_domain || '',
      cp_policy_package:   device?.cp_policy_package || '',
      cp_management_type:  device?.cp_management_type || 'SmartCenter',
      sync_interval_hours: device?.sync_interval_hours?.toString() || '',
    },
  })

  const vendor = watch('vendor')
  const cpMgmtType = watch('cp_management_type')

  const onSubmit = async (vals: FormValues) => {
    setSaving(true); setError('')
    try {
      const payload: Record<string, unknown> = {
        customer_id:         customerId,
        name:                vals.name,
        vendor:              vals.vendor,
        host:                vals.host,
        port:                vals.port ? parseInt(vals.port) : null,
        use_ssl:             vals.use_ssl,
        verify_ssl:          vals.verify_ssl,
        vdom:                vals.vdom || 'root',
        cp_domain:           vals.cp_domain || null,
        cp_policy_package:   vals.cp_policy_package || null,
        cp_management_type:  vals.vendor === 'CheckPoint' ? vals.cp_management_type : null,
      }
      if (vals.api_token) payload.api_token = vals.api_token
      if (vals.username)  payload.username = vals.username
      if (vals.password)  payload.password = vals.password
      payload.sync_interval_hours = vals.sync_interval_hours ? parseInt(vals.sync_interval_hours) : null

      if (device) {
        await updateDevice(device.id, payload)
      } else {
        await createDevice(payload)
      }
      onSaved(); onClose()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to save.'
      setError(msg)
    } finally { setSaving(false) }
  }

  const handleTest = async () => {
    if (!device) return
    setTesting(true); setTestSuccess(null); setTestError(null); setTestHint(null)
    setTestPhases([]); setTestInfo(null)
    try {
      const res = await testDevice(device.id)
      setTestPhases(res.phases || [])
      if (res.success) {
        setTestSuccess(true)
        setTestInfo(res.info || null)
      } else {
        setTestSuccess(false)
        setTestError(res.error || 'Connection failed')
        setTestHint(res.hint || null)
      }
    } catch (e) {
      setTestSuccess(false)
      setTestError(String(e))
    } finally { setTesting(false) }
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col">
        <DialogHeader className="px-6 py-4 bg-[#0f2744] rounded-t-xl space-y-0 flex-shrink-0">
          <DialogTitle className="text-white font-semibold flex items-center gap-2">
            <Server className="w-4 h-4" /> {device ? 'Edit Device' : 'Add Firewall Device'}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-4 overflow-y-auto">
          {/* Basic */}
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="label-sm">Device Name *</label>
              <input {...register('name', { required: 'Required' })}
                className="input-sm w-full" placeholder="e.g. HQ Firewall" />
              {errors.name && <p className="text-red-500 text-xs mt-0.5">{errors.name.message}</p>}
            </div>

            <div>
              <label className="label-sm">Vendor *</label>
              <select {...register('vendor')} className="input-sm w-full">
                <option value="FortiGate">FortiGate</option>
                <option value="CheckPoint">Check Point</option>
                <option value="PaloAlto">Palo Alto Networks</option>
                <option value="CiscoASA">Cisco ASA</option>
                <option value="HuaweiUSG">Huawei USG</option>
              </select>
            </div>

            <div>
              <label className="label-sm">Host / IP *</label>
              <input {...register('host', { required: 'Required' })}
                className="input-sm w-full" placeholder="192.168.1.1" />
              {errors.host && <p className="text-red-500 text-xs mt-0.5">{errors.host.message}</p>}
            </div>

            <div>
              <label className="label-sm">Port</label>
              <input {...register('port')} className="input-sm w-full"
                placeholder={
                  vendor === 'CheckPoint' ? '443 or 4434'
                  : vendor === 'HuaweiUSG' ? '22 (SSH) or 443 (REST)'
                  : '443'
                } type="number" />
              {vendor === 'HuaweiUSG' && (
                <p className="text-[11px] text-blue-600 mt-0.5">
                  Port 22 → SSH (recommended) · Port 443/8443 → HTTPS REST API
                </p>
              )}
            </div>

            {vendor !== 'HuaweiUSG' && (
              <div className="flex flex-col gap-2 pt-4">
                <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                  <input type="checkbox" {...register('use_ssl')} className="rounded" />
                  Use HTTPS
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                  <input type="checkbox" {...register('verify_ssl')} className="rounded" />
                  Verify SSL cert
                </label>
              </div>
            )}
          </div>

          {/* Auth section */}
          <div className="border-t border-gray-100 pt-4 space-y-3">
            <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wide">Authentication</h3>

            {/* Shared username / password */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label-sm">
                  Username
                  {device && <span className="text-gray-400 font-normal ml-1">(leave blank to keep existing)</span>}
                </label>
                <input {...register('username')} className="input-sm w-full"
                  placeholder={device?.username_hint ? `current: ${device.username_hint}` : 'admin'} />
              </div>
              <div>
                <label className="label-sm">Password</label>
                <div className="relative">
                  <input {...register('password')} type={showPass ? 'text' : 'password'}
                    className="input-sm w-full pr-8" />
                  <button type="button" onClick={() => setShowPass(p => !p)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                    {showPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* FortiGate extras */}
            {vendor === 'FortiGate' && (
              <div className="space-y-2 bg-orange-50 rounded-lg p-3">
                <p className="text-xs text-orange-700 font-medium">FortiGate — API Token (recommended over password)</p>
                <div>
                  <label className="label-sm">API Token</label>
                  <input {...register('api_token')} type="password"
                    className="input-sm w-full font-mono" placeholder="REST API token" />
                  <p className="text-xs text-gray-400 mt-0.5">System › Administrators › Create REST API Admin › Read-only profile</p>
                </div>
                <div>
                  <label className="label-sm">VDOM <span className="text-gray-400 font-normal">(default: root)</span></label>
                  <input {...register('vdom')} className="input-sm w-full" placeholder="root" />
                </div>
              </div>
            )}

            {/* Palo Alto extras */}
            {vendor === 'PaloAlto' && (
              <div className="space-y-2 bg-purple-50 rounded-lg p-3">
                <p className="text-xs text-purple-700 font-medium">Palo Alto — API Key (recommended)</p>
                <div>
                  <label className="label-sm">API Key</label>
                  <input {...register('api_token')} type="password"
                    className="input-sm w-full font-mono" placeholder="PAN-OS API key" />
                  <p className="text-xs text-gray-400 mt-0.5">GET /api/?type=keygen&user=U&password=P</p>
                </div>
                <div>
                  <label className="label-sm">VSYS</label>
                  <input {...register('vdom')} className="input-sm w-full" placeholder="vsys1" />
                </div>
              </div>
            )}

            {/* Check Point extras */}
            {vendor === 'CheckPoint' && (
              <div className="space-y-3 bg-teal-50 rounded-lg p-3">
                <p className="text-xs text-teal-700 font-medium">
                  Connects to the <strong>Check Point Management Server</strong> (not gateway) — same approach as Tufin SecureTrack.
                </p>

                {/* Management server type */}
                <div>
                  <label className="label-sm">Management Server Type</label>
                  <select {...register('cp_management_type')} className="input-sm w-full">
                    <option value="SmartCenter">SmartCenter (single domain)</option>
                    <option value="MDS">MDS / Multi-Domain Server</option>
                    <option value="Smart-1Cloud">Smart-1 Cloud</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {/* Domain / CMA — only relevant for MDS */}
                  <div>
                    <label className="label-sm">
                      Domain / CMA
                      {cpMgmtType === 'MDS'
                        ? <span className="text-teal-600 ml-1">(required for MDS)</span>
                        : <span className="text-gray-400 ml-1">(optional)</span>}
                    </label>
                    <input {...register('cp_domain')} className="input-sm w-full"
                      placeholder={cpMgmtType === 'MDS' ? 'CMA name' : '(leave empty)'} />
                    {cpMgmtType === 'MDS' && (
                      <p className="text-xs text-gray-400 mt-0.5">Use Test Connection to discover domains</p>
                    )}
                  </div>

                  {/* Policy package */}
                  <div>
                    <label className="label-sm">Policy Package</label>
                    <input {...register('cp_policy_package')} className="input-sm w-full"
                      placeholder="Network (auto-detected)" />
                    <p className="text-xs text-gray-400 mt-0.5">Use Test Connection to see all packages</p>
                  </div>
                </div>

                <div className="text-xs text-gray-500 space-y-0.5 pt-1 border-t border-teal-200">
                  <p>Required: read-only API user · API access enabled · Management API running</p>
                  <p>Port: 443 (default) · 4434 for Smart-1 appliances · 443 for Smart-1 Cloud</p>
                </div>
              </div>
            )}

            {/* Cisco ASA note */}
            {vendor === 'CiscoASA' && (
              <div className="bg-blue-50 rounded-lg p-3 text-xs text-blue-700">
                Token-based auth via REST API. Privilege level 5+ required. Hit counts parsed from CLI passthrough.
              </div>
            )}

            {/* Huawei USG info */}
            {vendor === 'HuaweiUSG' && (
              <div className="space-y-2 bg-red-50 rounded-lg p-3">
                <p className="text-xs text-red-700 font-semibold">Huawei USG — SSH (recommended) or HTTPS REST API</p>
                <div className="text-xs text-red-700 space-y-1">
                  <p><strong>SSH (port 22):</strong> Connects via SSH and runs read-only <code>display</code> commands to retrieve the full running configuration, security policies, address sets, service sets, zones, NAT, and statistics.</p>
                  <p><strong>REST API (port 443 / 8443):</strong> Uses the Huawei USG HTTPS REST API. Requires the eAPI service to be enabled on the device.</p>
                </div>
                <div className="text-xs text-gray-500 space-y-0.5 pt-1 border-t border-red-200">
                  <p className="font-medium text-gray-600">SSH prerequisites:</p>
                  <p>• SSH service enabled: <code>ssh server enable</code></p>
                  <p>• User with read-only operator role (or higher)</p>
                  <p>• Management ACL allows this server's IP on port 22</p>
                  <p className="font-medium text-gray-600 pt-1">Supported platforms:</p>
                  <p>USG2000 · USG5000 · USG6000 · USG6000E · USG6000F · USG9000</p>
                </div>
              </div>
            )}
          </div>

          {/* ── Diagnostic phases ── */}
          {testPhases.length > 0 && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 space-y-1.5">
              <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Connection Diagnostics</p>
              {testPhases.map((ph, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  {ph.ok
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-green-500 mt-0.5 shrink-0" />
                    : <XCircle className="w-3.5 h-3.5 text-red-500 mt-0.5 shrink-0" />}
                  <div>
                    <span className={clsx('font-semibold', ph.ok ? 'text-gray-700' : 'text-red-700')}>{ph.phase}</span>
                    <span className="text-gray-400 ml-1">— {ph.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Failure panel ── */}
          {testSuccess === false && testError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 space-y-2">
              <div className="flex items-start gap-2 text-sm text-red-700">
                <XCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span className="font-medium">{testError}</span>
              </div>
              {testHint && (
                <div className="text-xs text-red-600 bg-white border border-red-100 rounded p-2 whitespace-pre-line leading-relaxed">
                  {testHint}
                </div>
              )}
            </div>
          )}

          {/* ── Success panel ── */}
          {testSuccess === true && testInfo && (
            <div className="rounded-lg border border-green-200 bg-green-50 p-3 space-y-2">
              <div className="flex items-center gap-2 text-green-700 text-sm font-medium">
                <CheckCircle2 className="w-4 h-4" /> Connected successfully
              </div>

              {/* FortiGate */}
              {testInfo.hostname && (
                <div className="text-xs text-gray-600 space-y-0.5">
                  {[
                    ['Hostname', testInfo.hostname],
                    ['Version',  testInfo.version],
                    ['Serial',   testInfo.serial],
                    ['Rules',    testInfo.rule_count != null ? String(testInfo.rule_count) : null],
                    ['Interfaces', testInfo.interface_count != null ? String(testInfo.interface_count) : null],
                    ['Zones',    testInfo.zone_count != null ? String(testInfo.zone_count) : null],
                  ].filter(([, v]) => v).map(([k, v]) => (
                    <p key={k as string}><span className="font-medium">{k}:</span> {v}</p>
                  ))}
                  {testInfo.vdoms && testInfo.vdoms.length > 1 && (
                    <p><span className="font-medium">VDOMs:</span> {testInfo.vdoms.join(', ')}</p>
                  )}
                </div>
              )}

              {/* CheckPoint */}
              {testInfo.api_server_version && (
                <div className="text-xs text-gray-600 space-y-1">
                  <p><span className="font-medium">API Version:</span> {testInfo.api_server_version}</p>
                  <p><span className="font-medium">Type:</span> {testInfo.is_mds ? '🏢 Multi-Domain (MDS)' : testInfo.management_type || 'SmartCenter'}</p>

                  {testInfo.is_mds && testInfo.domains && testInfo.domains.length > 0 && (
                    <div>
                      <p className="font-medium text-gray-700">Domains ({testInfo.domains.length}):</p>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {testInfo.domains.map(d => (
                          <span key={d.uid} className="bg-teal-100 text-teal-700 px-1.5 py-0.5 rounded text-xs">{d.name}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {testInfo.packages && testInfo.packages.length > 0 && (
                    <div>
                      <p className="font-medium text-gray-700">Policy Packages ({testInfo.packages.length}):</p>
                      <div className="space-y-0.5 mt-0.5">
                        {testInfo.packages.map(pkg => (
                          <div key={pkg.name} className="flex items-start gap-1">
                            <span className="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-xs font-medium shrink-0">{pkg.name}</span>
                            {pkg.access_layers.length > 0 && (
                              <span className="text-gray-400 text-xs">layers: {pkg.access_layers.join(', ')}</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {testInfo.gateways && testInfo.gateways.length > 0 && (
                    <div>
                      <p className="font-medium text-gray-700">Gateways ({testInfo.gateways.length}):</p>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {testInfo.gateways.slice(0, 8).map(gw => (
                          <span key={gw.name} className="bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded text-xs">{gw.name}</span>
                        ))}
                        {testInfo.gateways.length > 8 && <span className="text-gray-400 text-xs">+{testInfo.gateways.length - 8} more</span>}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Palo Alto */}
              {testInfo.model && (
                <div className="text-xs text-gray-600 space-y-0.5">
                  {[
                    ['Model',      testInfo.model],
                    ['PAN-OS',     testInfo.version || testInfo.sw_version],
                    ['Rules',      testInfo.rule_count != null ? String(testInfo.rule_count) : null],
                    ['Objects',    testInfo.object_count != null ? String(testInfo.object_count) : null],
                    ['App Defs',   testInfo.app_count != null ? String(testInfo.app_count) : null],
                  ].filter(([, v]) => v).map(([k, v]) => (
                    <p key={k as string}><span className="font-medium">{k}:</span> {v}</p>
                  ))}
                  {testInfo.vsys_list && testInfo.vsys_list.length > 0 && (
                    <p><span className="font-medium">vsys:</span> {testInfo.vsys_list.join(', ')}</p>
                  )}
                </div>
              )}

              {/* Cisco ASA */}
              {(testInfo.software_version || (testInfo.rule_count != null && !testInfo.hostname && !testInfo.model && !testInfo.api_server_version && !testInfo.zone_count)) && (
                <div className="text-xs text-gray-600 space-y-0.5">
                  {[
                    ['ASA Version', testInfo.software_version || testInfo.version],
                    ['ACL Rules',   testInfo.rule_count != null ? String(testInfo.rule_count) : null],
                    ['Interfaces',  testInfo.interface_count != null ? String(testInfo.interface_count) : null],
                    ['Net Objects', testInfo.object_count != null ? String(testInfo.object_count) : null],
                  ].filter(([, v]) => v).map(([k, v]) => (
                    <p key={k as string}><span className="font-medium">{k}:</span> {v}</p>
                  ))}
                </div>
              )}

              {/* Huawei USG */}
              {testInfo.zone_count != null && !testInfo.hostname && !testInfo.model && !testInfo.api_server_version && (
                <div className="text-xs text-gray-600 space-y-0.5">
                  {[
                    ['VRP Version', testInfo.version],
                    ['Model',       testInfo.model],
                    ['Security Rules', testInfo.rule_count != null ? String(testInfo.rule_count) : null],
                    ['Zones',       testInfo.zone_count != null ? String(testInfo.zone_count) : null],
                    ['Addr Objects', testInfo.object_count != null ? String(testInfo.object_count) : null],
                  ].filter(([, v]) => v).map(([k, v]) => (
                    <p key={k as string}><span className="font-medium">{k}:</span> {v}</p>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Auto-sync schedule */}
          <div className="border-t border-gray-100 pt-4">
            <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wide mb-2">Auto-Sync Schedule</h3>
            <div>
              <label className="label-sm">Sync Interval</label>
              <select {...register('sync_interval_hours')} className="input-sm w-full">
                <option value="">Disabled (manual only)</option>
                <option value="6">Every 6 hours</option>
                <option value="12">Every 12 hours</option>
                <option value="24">Daily (24h)</option>
                <option value="48">Every 2 days</option>
                <option value="168">Weekly</option>
              </select>
              <p className="text-xs text-gray-400 mt-0.5">
                The server checks every 5 minutes and triggers sync when the interval has elapsed.
              </p>
            </div>
          </div>

          {error && <p className="text-red-600 text-sm bg-red-50 rounded-lg px-3 py-2">{error}</p>}

          <div className="flex justify-between pt-2 border-t border-gray-100">
            <div>
              {device && (
                <button type="button" onClick={handleTest} disabled={testing}
                  className="btn-secondary flex items-center gap-1.5 text-sm">
                  <Wifi className="w-3.5 h-3.5" />
                  {testing ? 'Testing…' : 'Test Connection'}
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
              <button type="submit" disabled={saving} className="btn-primary">
                {saving ? 'Saving…' : device ? 'Save' : 'Add Device'}
              </button>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ── Device Detail Drawer ───────────────────────────────────────────────────────
interface DeviceInterface { name: string; ip: string; mask: string; type: string; status: string }
interface CVEEntry {
  cve_id: string; description: string; cvss_score: number | null
  cvss_severity: string; url: string; published: string
}

function DeviceDetailDrawer({ device, onClose, onEdit }: {
  device: FirewallDeviceT
  onClose: () => void
  onEdit: () => void
}) {
  const interfaces: DeviceInterface[] = (() => {
    try { return device.device_interfaces ? JSON.parse(device.device_interfaces) : [] }
    catch { return [] }
  })()

  const [cveData, setCveData]     = useState<{ cves: CVEEntry[]; error?: string; cached?: boolean } | null>(null)
  const [cveLoading, setCveLoading] = useState(false)

  /** For CheckPoint, os_version may be "API 2.0.1" (management API ver).
   *  Prefer extracting the real GW firmware version (e.g. "R81.20") from fw_model. */
  const displayOsVersion: string | null = (() => {
    const ov = device.os_version || null
    if (device.vendor === 'CheckPoint' && ov && /^API\s/i.test(ov) && device.fw_model) {
      const m = device.fw_model.match(/[Rr]\d+(?:\.\d+)?/)
      if (m) return m[0]
    }
    return ov
  })()

  const loadCVEs = async (refresh = false) => {
    if (!device.os_version) return
    setCveLoading(true)
    try {
      const { getDeviceVulnerabilities } = await import('../api/client')
      const result = await getDeviceVulnerabilities(device.id, refresh)
      setCveData(result)
    } catch { setCveData({ cves: [], error: 'Failed to load CVE data' }) }
    finally { setCveLoading(false) }
  }

  const vc = VENDOR_COLOR_MAP[device.vendor] ?? { bar: 'bg-slate-500', accent: 'from-slate-500 to-slate-700', chip: 'bg-gray-100 text-gray-700 border-gray-200' }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/20" />

      {/* Panel */}
      <div
        className="relative w-[480px] max-w-full h-full bg-white shadow-2xl flex flex-col overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className={`bg-gradient-to-r ${vc.accent} px-6 py-5 text-white flex-shrink-0`}>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold leading-tight">{device.name}</h2>
                <p className="text-white/70 text-sm font-mono">{device.host}{device.port ? `:${device.port}` : ''}</p>
              </div>
            </div>
            <button onClick={onClose} className="w-8 h-8 rounded-lg bg-white/10 hover:bg-white/20 flex items-center justify-center transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex flex-wrap gap-2 mt-4">
            <span className="bg-white/15 text-white text-xs font-semibold px-2.5 py-1 rounded-full">{device.vendor}</span>
            {device.criticality && (
              <span className="bg-white/15 text-white text-xs font-semibold px-2.5 py-1 rounded-full capitalize">{device.criticality} criticality</span>
            )}
            {device.environment_type && device.environment_type !== 'production' && (
              <span className="bg-amber-400/80 text-amber-900 text-xs font-semibold px-2.5 py-1 rounded-full capitalize">{device.environment_type}</span>
            )}
            <SyncStatusChip status={device.sync_status} />
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto">

          {/* System info */}
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <Cpu className="w-3 h-3" /> System Information
            </h3>
            <div className="space-y-2">
              {[
                { label: 'OS / Firmware', value: displayOsVersion },
                { label: 'Model', value: device.fw_model },
                { label: 'Serial Number', value: device.serial_number },
                { label: 'Management Platform', value: device.management_platform },
                { label: 'HA Mode', value: device.ha_mode },
                { label: 'HA Peer', value: device.ha_peer },
              ].map(({ label, value }) => value ? (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">{label}</span>
                  <span className="text-xs font-semibold text-gray-800 font-mono bg-gray-50 border border-gray-100 px-2 py-0.5 rounded max-w-[240px] truncate">{value}</span>
                </div>
              ) : null)}
              {!device.os_version && !device.fw_model && (
                <p className="text-xs text-gray-400 italic">Sync the device to populate system info.</p>
              )}
            </div>
          </div>

          {/* Network interfaces */}
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <Network className="w-3 h-3" /> Network Interfaces
            </h3>
            {interfaces.length > 0 ? (
              <div className="space-y-1.5">
                {interfaces.map((iface, i) => (
                  <div key={i} className="flex items-center gap-3 bg-gray-50 border border-gray-100 rounded-lg px-3 py-2">
                    <div className={clsx(
                      'w-2 h-2 rounded-full flex-shrink-0',
                      iface.status === 'up' || iface.status === 'enable' ? 'bg-green-500' : 'bg-gray-300'
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-gray-800 truncate">{iface.name}</p>
                      {iface.type && <p className="text-[10px] text-gray-400 capitalize">{iface.type}</p>}
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-xs font-mono text-gray-700">{iface.ip}</p>
                      {iface.mask && <p className="text-[10px] text-gray-400 font-mono">{iface.mask}</p>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 bg-gray-50 rounded-lg border border-dashed border-gray-200">
                <Globe className="w-6 h-6 text-gray-300 mx-auto mb-1" />
                <p className="text-xs text-gray-400">No interface data yet</p>
                <p className="text-[11px] text-gray-300 mt-0.5">Sync the device to discover interfaces</p>
              </div>
            )}
          </div>

          {/* Connection details */}
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <Shield className="w-3 h-3" /> Connection Details
            </h3>
            <div className="space-y-2">
              {[
                { label: 'Host / IP', value: `${device.host}${device.port ? ':' + device.port : ''}` },
                { label: 'Protocol', value: device.use_ssl ? 'HTTPS' : 'HTTP' },
                { label: 'SSL Verify', value: device.verify_ssl ? 'Enabled' : 'Disabled (self-signed)' },
                { label: 'Auth Method', value: device.has_token ? 'API Token' : device.has_credentials ? 'Username / Password' : 'None' },
                { label: 'Username', value: device.username_hint || undefined },
                device.vendor === 'FortiGate' ? { label: 'VDOM', value: device.vdom || 'root' } : null,
                device.vendor === 'CheckPoint' ? { label: 'Domain', value: device.cp_domain || undefined } : null,
                device.vendor === 'CheckPoint' ? { label: 'Policy Package', value: device.cp_policy_package || undefined } : null,
                device.vendor === 'CheckPoint' ? { label: 'Mgmt Type', value: device.cp_management_type || undefined } : null,
              ].filter(Boolean).map(row => row && row.value ? (
                <div key={row.label} className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">{row.label}</span>
                  <span className="text-xs font-semibold text-gray-800 font-mono">{row.value}</span>
                </div>
              ) : null)}
            </div>
          </div>

          {/* Deployment info */}
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <MapPin className="w-3 h-3" /> Deployment
            </h3>
            <div className="space-y-2">
              {[
                { label: 'Role', value: device.fw_role },
                { label: 'Location', value: device.location },
                { label: 'Environment', value: device.environment_type },
                { label: 'Criticality', value: device.criticality },
                { label: 'Auto-Sync', value: device.sync_interval_hours ? `Every ${device.sync_interval_hours}h` : 'Disabled' },
                { label: 'Last Sync', value: device.last_sync_at ? new Date(device.last_sync_at).toLocaleString() : 'Never' },
                { label: 'Last Policy', value: device.last_policy_id ? device.last_policy_id.slice(0, 8) + '…' : '—' },
                { label: 'Added', value: device.created_at ? new Date(device.created_at).toLocaleDateString() : '—' },
              ].map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">{label}</span>
                  <span className="text-xs font-semibold text-gray-800 capitalize">{value || '—'}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Error */}
          {device.last_error && (
            <div className="px-6 py-4 border-b border-gray-100">
              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <AlertCircle className="w-3 h-3 text-red-400" /> Last Error
              </h3>
              <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                <p className="text-xs text-red-700 break-words">{device.last_error}</p>
              </div>
            </div>
          )}

          {/* CVE Vulnerability Check */}
          <div className="px-6 py-4">
            <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <Shield className="w-3 h-3" /> CVE Vulnerability Check
            </h3>
            {!device.os_version ? (
              <p className="text-xs text-gray-400 italic">Sync device to discover OS version for CVE lookup.</p>
            ) : !cveData ? (
              <button
                onClick={() => loadCVEs()}
                disabled={cveLoading}
                className="flex items-center gap-2 text-xs px-3 py-2 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg text-blue-700 font-medium transition-colors"
              >
                <RefreshCw className={clsx('w-3 h-3', cveLoading && 'animate-spin')} />
                {cveLoading ? 'Querying NVD…' : `Check CVEs for ${displayOsVersion}`}
              </button>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-gray-600">
                    {cveData.cves.length > 0
                      ? <span className="font-semibold text-red-600">{cveData.cves.length} CVE(s) found</span>
                      : <span className="font-semibold text-green-600">No CVEs found</span>
                    } for {displayOsVersion}
                    {cveData.cached && <span className="text-gray-400 ml-1">(cached)</span>}
                  </p>
                  <button onClick={() => loadCVEs(true)} className="text-[10px] text-blue-500 hover:underline">Refresh</button>
                </div>
                {cveData.error && <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded p-2">{cveData.error}</p>}
                {cveData.cves.slice(0, 5).map(cve => (
                  <div key={cve.cve_id} className="bg-gray-50 border border-gray-200 rounded-lg p-2.5">
                    <div className="flex items-center justify-between mb-1">
                      <a href={cve.url} target="_blank" rel="noopener" className="text-xs font-bold text-blue-600 hover:underline">{cve.cve_id}</a>
                      <span className={clsx(
                        'text-[10px] font-bold px-1.5 py-0.5 rounded',
                        cve.cvss_severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                        cve.cvss_severity === 'HIGH'     ? 'bg-orange-100 text-orange-700' :
                        cve.cvss_severity === 'MEDIUM'   ? 'bg-amber-100 text-amber-700' :
                        'bg-gray-100 text-gray-600'
                      )}>
                        {cve.cvss_score ? `CVSS ${cve.cvss_score}` : cve.cvss_severity}
                      </span>
                    </div>
                    <p className="text-[10px] text-gray-600 line-clamp-2">{cve.description}</p>
                  </div>
                ))}
                {cveData.cves.length > 5 && (
                  <p className="text-xs text-gray-400 text-center">+{cveData.cves.length - 5} more — <a href={`https://nvd.nist.gov/vuln/search/results?query=${device.vendor}+${displayOsVersion}`} target="_blank" rel="noopener" className="text-blue-500 hover:underline">view all on NVD</a></p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer actions */}
        <div className="flex-shrink-0 border-t border-gray-100 px-6 py-4 flex gap-2 bg-gray-50">
          <button onClick={onEdit} className="btn-secondary flex items-center gap-1.5 flex-1 justify-center">
            <Settings className="w-3.5 h-3.5" /> Edit Device
          </button>
          {device.last_policy_id && (
            <Link
              to={`/policies/${device.last_policy_id}/rules`}
              className="btn-secondary flex items-center gap-1.5 flex-1 justify-center"
            >
              <Activity className="w-3.5 h-3.5" /> View Policy
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}

// Vendor color map shared by card and drawer
const VENDOR_COLOR_MAP: Record<string, { chip: string; accent: string; bar: string }> = {
  FortiGate:  { chip: 'bg-orange-100 text-orange-700 border-orange-200', accent: 'from-orange-500 to-orange-700',  bar: 'bg-orange-500' },
  CheckPoint: { chip: 'bg-teal-100 text-teal-700 border-teal-200',       accent: 'from-teal-500 to-teal-700',      bar: 'bg-teal-500'   },
  PaloAlto:   { chip: 'bg-purple-100 text-purple-700 border-purple-200', accent: 'from-purple-500 to-purple-700',  bar: 'bg-purple-500' },
  CiscoASA:   { chip: 'bg-blue-100 text-blue-700 border-blue-200',       accent: 'from-blue-500 to-blue-700',      bar: 'bg-blue-500'   },
  HuaweiUSG:  { chip: 'bg-red-100 text-red-700 border-red-200',          accent: 'from-red-500 to-red-700',        bar: 'bg-red-500'    },
}

// ── Device card ───────────────────────────────────────────────────────────────
const VENDOR_COLORS: Record<string, { chip: string; accent: string; bar: string }> = {
  FortiGate:  { chip: 'bg-orange-100 text-orange-700 border-orange-200', accent: 'from-orange-500 to-orange-700',  bar: 'bg-orange-500' },
  CheckPoint: { chip: 'bg-teal-100 text-teal-700 border-teal-200',       accent: 'from-teal-500 to-teal-700',      bar: 'bg-teal-500'   },
  PaloAlto:   { chip: 'bg-purple-100 text-purple-700 border-purple-200', accent: 'from-purple-500 to-purple-700',  bar: 'bg-purple-500' },
  CiscoASA:   { chip: 'bg-blue-100 text-blue-700 border-blue-200',       accent: 'from-blue-500 to-blue-700',      bar: 'bg-blue-500'   },
  HuaweiUSG:  { chip: 'bg-red-100 text-red-700 border-red-200',          accent: 'from-red-500 to-red-700',        bar: 'bg-red-500'    },
}
const CRITICALITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high:     'bg-orange-100 text-orange-700',
  medium:   'bg-amber-100 text-amber-700',
  low:      'bg-gray-100 text-gray-500',
}
const ROLE_LABELS: Record<string, string> = {
  perimeter:   'Perimeter',
  internal:    'Internal',
  dmz:         'DMZ',
  data_center: 'Data Centre',
  remote:      'Remote Access',
}

function DeviceCard({
  device,
  customerId,
  onEdit,
  onDelete,
  onSync,
  onResetSync,
  onClick,
  syncing,
}: {
  device: FirewallDeviceT
  customerId: string
  onEdit: () => void
  onDelete: () => void
  onSync: () => void
  onResetSync: () => void
  onClick: () => void
  syncing: boolean
}) {
  const vc = VENDOR_COLOR_MAP[device.vendor] ?? { chip: 'bg-gray-100 text-gray-700 border-gray-200', accent: 'from-slate-500 to-slate-700', bar: 'bg-slate-500' }

  const cardOsVersion: string | null = (() => {
    const ov = device.os_version || null
    if (device.vendor === 'CheckPoint' && ov && /^API\s/i.test(ov) && device.fw_model) {
      const m = device.fw_model.match(/[Rr]\d+(?:\.\d+)?/)
      if (m) return m[0]
    }
    return ov
  })()

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm hover:shadow-md transition-all overflow-hidden cursor-pointer" onClick={onClick}>
      {/* Vendor accent bar */}
      <div className={clsx('h-1 w-full', vc.bar)} />

      <div className="p-5">
        {/* Top row — name + vendor + status */}
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={clsx('w-10 h-10 rounded-xl bg-gradient-to-br flex items-center justify-center flex-shrink-0 shadow-sm', vc.accent)}>
              <Server className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0">
              <h3 className="font-bold text-gray-900 truncate">{device.name}</h3>
              <p className="text-xs text-gray-400 font-mono">{device.host}{device.port ? `:${device.port}` : ''}</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-1 flex-shrink-0 ml-2">
            <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded-full border', vc.chip)}>
              {device.vendor}
            </span>
            {device.criticality && (
              <span className={clsx('text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide', CRITICALITY_COLORS[device.criticality] ?? 'bg-gray-100 text-gray-500')}>
                {device.criticality}
              </span>
            )}
          </div>
        </div>

        {/* ── Device details panel ── */}
        <div className="bg-slate-50 rounded-lg px-3 py-2.5 mb-3 space-y-1.5">
          {/* OS / Firmware version — primary detail */}
          {cardOsVersion ? (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Version</span>
              <span className="text-xs font-mono font-semibold text-slate-700 bg-white border border-slate-200 px-2 py-0.5 rounded">
                {cardOsVersion}
              </span>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Version</span>
              <span className="text-[11px] text-slate-400 italic">Not yet synced</span>
            </div>
          )}

          {/* Model */}
          {device.fw_model ? (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Model</span>
              <span className="text-xs font-semibold text-slate-700">{device.fw_model}</span>
            </div>
          ) : null}

          {/* Management platform */}
          {device.management_platform ? (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Platform</span>
              <span className="text-xs text-slate-600">{device.management_platform}</span>
            </div>
          ) : null}

          {/* Role + Location */}
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Role</span>
            <span className="text-xs text-slate-600">
              {ROLE_LABELS[device.fw_role] || device.fw_role || 'Perimeter'}
              {device.location ? <span className="text-slate-400"> · {device.location}</span> : null}
            </span>
          </div>

          {/* Environment */}
          {device.environment_type && device.environment_type !== 'production' ? (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">Env</span>
              <span className="text-xs text-amber-600 font-semibold capitalize">{device.environment_type}</span>
            </div>
          ) : null}

          {/* VDOM (FortiGate) */}
          {device.vdom && device.vdom !== 'root' ? (
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wide">VDOM</span>
              <span className="text-xs font-mono text-slate-600">{device.vdom}</span>
            </div>
          ) : null}
        </div>

        {/* Sync status row */}
        <div className="flex items-center gap-2 mb-3">
          <SyncStatusChip status={device.sync_status} />
          {device.last_sync_at ? (
            <span className="text-xs text-gray-400">
              {new Date(device.last_sync_at).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}
            </span>
          ) : (
            <span className="text-xs text-gray-400">No sync yet</span>
          )}
          {device.sync_interval_hours ? (
            <span className="ml-auto bg-purple-50 text-purple-600 px-2 py-0.5 rounded text-[10px] font-semibold flex items-center gap-1">
              <Clock className="w-3 h-3" />
              Auto {device.sync_interval_hours >= 168 ? 'weekly' : device.sync_interval_hours >= 48 ? `${device.sync_interval_hours/24}d` : `${device.sync_interval_hours}h`}
            </span>
          ) : null}
        </div>

        {device.last_error && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-3">
            <p className="text-xs text-red-700 line-clamp-2">{device.last_error}</p>
          </div>
        )}

        {/* Auth pills */}
        <div className="flex flex-wrap gap-1.5 mb-4">
          {device.has_token && (
            <span className="bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full text-[10px] font-semibold border border-blue-100">API Token</span>
          )}
          {device.has_credentials && !device.has_token && (
            <span className="bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full text-[10px] font-semibold">Credentials</span>
          )}
          {device.use_ssl && <span className="text-[10px] text-green-600 font-semibold bg-green-50 px-2 py-0.5 rounded-full border border-green-100">HTTPS</span>}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 border-t border-gray-100 pt-3" onClick={e => e.stopPropagation()}>
          <button
            onClick={onSync}
            disabled={syncing || device.sync_status === 'running'}
            className={clsx(
              'flex-1 flex items-center justify-center gap-1.5 text-sm py-1.5 rounded-lg font-medium transition-colors',
              syncing || device.sync_status === 'running'
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            )}
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', (syncing || device.sync_status === 'running') && 'animate-spin')} />
            {device.sync_status === 'running' ? 'Syncing…' : 'Sync Now'}
          </button>
          {device.sync_status === 'running' && (
            <button
              onClick={e => { e.stopPropagation(); onResetSync() }}
              title="Force reset stuck sync"
              className="flex items-center gap-1 text-xs px-2 py-1.5 rounded-lg border border-red-200 text-red-500 hover:bg-red-50 transition-colors"
            >
              <X className="w-3 h-3" /> Reset
            </button>
          )}
          {device.last_policy_id && (
            <Link
              to={`/policies/${device.last_policy_id}/rules`}
              className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-blue-600"
              title="View rules"
            >
              <Activity className="w-4 h-4" />
            </Link>
          )}
          <Link
            to={`/customers/${customerId}/devices/${device.id}/history`}
            className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-purple-600"
            title="Revision history"
          >
            <History className="w-4 h-4" />
          </Link>
          <button onClick={onEdit}
            className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 hover:text-blue-600"
            title="Edit">
            <Settings className="w-4 h-4" />
          </button>
          <button onClick={onDelete}
            className="p-1.5 hover:bg-red-50 rounded-lg text-gray-400 hover:text-red-600"
            title="Delete">
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Devices page ─────────────────────────────────────────────────────────
export function Devices() {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id
  const [devices, setDevices] = useState<FirewallDeviceT[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState<FirewallDeviceT | undefined>()
  const [syncingId, setSyncingId] = useState<string | null>(null)
  const [detailDevice, setDetailDevice] = useState<FirewallDeviceT | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    getDevices(customerId || undefined).then(setDevices).finally(() => setLoading(false))
  }, [customerId])

  useEffect(() => { load() }, [load])

  // Poll while any device is syncing — exponential backoff (3s → 6s → 12s … max 30s)
  useEffect(() => {
    const running = devices.some(d => d.sync_status === 'running')
    if (!running) return
    let delay = 3000
    let tid: ReturnType<typeof setTimeout>
    let active = true
    const poll = async () => {
      if (!active) return
      const syncing = devices.filter(d => d.sync_status === 'running')
      let anyFinished = false
      await Promise.all(syncing.map(async d => {
        try {
          const s = await getDeviceSyncStatus(d.id)
          if (s.sync_status !== 'running') anyFinished = true
        } catch { /* ignore */ }
      }))
      if (anyFinished) { load(); return }
      delay = Math.min(delay * 2, 30_000)
      if (active) tid = setTimeout(poll, delay)
    }
    tid = setTimeout(poll, delay)
    return () => { active = false; clearTimeout(tid) }
  }, [devices, load])

  const handleSync = async (deviceId: string) => {
    setSyncingId(deviceId)
    try {
      await syncDevice(deviceId)
      // optimistically update status
      setDevices(ds => ds.map(d => d.id === deviceId ? { ...d, sync_status: 'running' } : d))
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Sync failed'
      alert(msg)
    } finally {
      setSyncingId(null)
    }
  }

  const handleDelete = async (d: FirewallDeviceT) => {
    if (!confirm(`Delete "${d.name}"? This will permanently delete all associated policies, rules, findings, and objects.`)) return
    await deleteDevice(d.id)
    load()
  }

  const handleResetSync = async (deviceId: string) => {
    try {
      await resetDeviceSync(deviceId)
      load()
    } catch { /* ignore */ }
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Live Firewall Devices</h1>
          <p className="text-gray-500 mt-1">
            Connect directly to firewalls to sync policies and monitor rule hit counts in real time.
          </p>
        </div>
        {customerId && (
          <button onClick={() => { setEditing(undefined); setShowModal(true) }}
            className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> Add Device
          </button>
        )}
      </div>

      {/* Info banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6 flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-800">
          <strong>Read-only monitoring mode.</strong> This tool connects to firewalls in read-only mode only.
          It never modifies, deletes, or reorders firewall rules. All recommendations require manual review
          and change approval before implementation.
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" />
        </div>
      ) : devices.length === 0 ? (
        <div className="text-center py-20 card">
          <WifiOff className="w-16 h-16 text-gray-200 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-600 mb-2">No devices connected</h2>
          <p className="text-gray-400 text-sm mb-6">
            {customerId
              ? <>Add a FortiGate or Check Point device to start live monitoring.<br />
                You can also <Link to={`/upload?customer_id=${customerId}`} className="text-blue-600 hover:underline">upload a policy file</Link> for offline analysis.</>
              : 'Navigate to a customer to add devices and start live monitoring.'}
          </p>
          {customerId && (
            <button onClick={() => { setEditing(undefined); setShowModal(true) }}
              className="btn-primary mx-auto flex items-center gap-2 w-fit">
              <Plus className="w-4 h-4" /> Add First Device
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {devices.map(d => (
            <DeviceCard
              key={d.id}
              device={d}
              customerId={customerId || d.customer_id}
              syncing={syncingId === d.id}
              onEdit={() => { setEditing(d); setShowModal(true) }}
              onDelete={() => handleDelete(d)}
              onSync={() => handleSync(d.id)}
              onResetSync={() => handleResetSync(d.id)}
              onClick={() => setDetailDevice(d)}
            />
          ))}
        </div>
      )}

      {detailDevice && (
        <DeviceDetailDrawer
          device={detailDevice}
          onClose={() => setDetailDevice(null)}
          onEdit={() => { const d = detailDevice; setDetailDevice(null); setEditing(d); setShowModal(true) }}
        />
      )}

      {showModal && (customerId || editing?.customer_id) && (
        <DeviceModal
          customerId={(customerId || editing?.customer_id)!}
          device={editing}
          onClose={() => setShowModal(false)}
          onSaved={load}
        />
      )}
    </div>
  )
}
