/**
 * Vulnerabilities — CVE & Firmware Advisory Dashboard
 * =====================================================
 * Surfaces CVE data that was previously buried 4 clicks deep inside the
 * Device detail drawer. Shows all live devices with their OS versions,
 * known CVEs (from NVD), and an overall exposure summary.
 *
 * SAFETY: Read-only. No device configuration is modified.
 * All advisories are informational — remediation requires engineer validation
 * and formal change approval.
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useCustomer } from '../contexts/CustomerContext'
import {
  Shield, AlertTriangle, RefreshCw, CheckCircle2,
  ExternalLink, ChevronDown, ChevronUp, Info, Server,
} from 'lucide-react'
import { clsx } from 'clsx'
import { getDevices, getDeviceVulnerabilities } from '../api/client'
import type { FirewallDeviceT } from '../types'

// ── Types ──────────────────────────────────────────────────────────────────────

interface CVEEntry {
  cve_id: string
  description: string
  cvss_score: number | null
  cvss_severity: string
  url: string
  published: string
}

interface DeviceVulnState {
  status: 'idle' | 'loading' | 'done' | 'error'
  cves: CVEEntry[]
  error?: string
  cached?: boolean
  os_version?: string | null
  queryable?: boolean
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function severityColor(s: string) {
  switch (s) {
    case 'CRITICAL': return 'bg-red-100 text-red-700 border-red-200'
    case 'HIGH':     return 'bg-orange-100 text-orange-700 border-orange-200'
    case 'MEDIUM':   return 'bg-amber-100 text-amber-700 border-amber-200'
    case 'LOW':      return 'bg-gray-100 text-gray-600 border-gray-200'
    default:         return 'bg-gray-100 text-gray-500 border-gray-100'
  }
}

function scoreLabel(score: number | null, severity: string) {
  if (score != null) return `CVSS ${score.toFixed(1)}`
  return severity || 'N/A'
}

function displayOsVersion(device: FirewallDeviceT): string | null {
  const ov = device.os_version || null
  if (device.vendor === 'CheckPoint' && ov && /^API\s/i.test(ov) && device.fw_model) {
    const m = device.fw_model.match(/[Rr]\d+(?:\.\d+)?/)
    if (m) return m[0]
  }
  if (device.vendor === 'CheckPoint' && ov && /^API\s/i.test(ov)) return null
  return ov
}

// ── Device row ─────────────────────────────────────────────────────────────────

function DeviceVulnRow({
  device, state, onLoad, onRefresh,
}: {
  device: FirewallDeviceT
  state: DeviceVulnState
  onLoad: () => void
  onRefresh: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  const critCount = state.cves.filter(c => c.cvss_severity === 'CRITICAL').length
  const highCount = state.cves.filter(c => c.cvss_severity === 'HIGH').length
  const hasData   = state.status === 'done'
  const noCVEs    = hasData && state.cves.length === 0 && !state.error
  const osVersion = displayOsVersion(device)

  return (
    <div className="card mb-3">
      {/* Device summary row */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Icon + name */}
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <div className={clsx(
            'w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0',
            device.sync_status === 'error' ? 'bg-red-50' : 'bg-slate-100'
          )}>
            <Server className={clsx('w-4 h-4', device.sync_status === 'error' ? 'text-red-400' : 'text-slate-500')} />
          </div>
          <div className="min-w-0">
            <p className="font-semibold text-gray-900 text-sm truncate">{device.name}</p>
            <p className="text-xs text-gray-400 truncate">
              {device.vendor} · {device.host}
              {osVersion ? ` · ${osVersion}` : ''}
            </p>
          </div>
        </div>

        {/* CVE summary chips */}
        {hasData && state.cves.length > 0 && (
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {critCount > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-700 border border-red-200">
                {critCount} Critical
              </span>
            )}
            {highCount > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 border border-orange-200">
                {highCount} High
              </span>
            )}
            {state.cves.length - critCount - highCount > 0 && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200">
                {state.cves.length - critCount - highCount} Other
              </span>
            )}
          </div>
        )}

        {noCVEs && (
          <span className="flex items-center gap-1 text-xs font-semibold text-emerald-600 flex-shrink-0">
            <CheckCircle2 className="w-3.5 h-3.5" /> No CVEs found
            {state.cached && <span className="text-gray-400 ml-0.5">(cached)</span>}
          </span>
        )}
        {hasData && state.error && (
          <span className="flex items-center gap-1 text-xs font-semibold text-amber-600 flex-shrink-0">
            <AlertTriangle className="w-3.5 h-3.5" /> CVE lookup unavailable
          </span>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 flex-shrink-0 ml-auto">
          {state.status === 'idle' && osVersion && (
            <button
              onClick={onLoad}
              className="text-xs px-3 py-1.5 bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-700 font-medium rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Shield className="w-3 h-3" /> Check CVEs
            </button>
          )}
          {state.status === 'idle' && !osVersion && (
            <span className="text-xs text-gray-400 italic">
              {device.vendor === 'CheckPoint' && device.os_version && /^API\s/i.test(device.os_version)
                ? 'Sync gateway inventory to discover firewall OS version'
                : 'Sync to discover OS version'}
            </span>
          )}
          {state.status === 'loading' && (
            <span className="flex items-center gap-1.5 text-xs text-blue-600">
              <RefreshCw className="w-3 h-3 animate-spin" /> Querying NVD…
            </span>
          )}
          {hasData && (
            <>
              <button
                onClick={onRefresh}
                className="text-[11px] text-blue-500 hover:underline flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
              {state.cves.length > 0 && (
                <button
                  onClick={() => setExpanded(e => !e)}
                  className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 transition-colors"
                >
                  {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  {expanded ? 'Collapse' : 'Show details'}
                </button>
              )}
            </>
          )}
          {state.status === 'error' && (
            <span className="text-xs text-red-500">{state.error}</span>
          )}
        </div>
      </div>

      {/* CVE detail list */}
      {expanded && state.cves.length > 0 && (
        <div className="mt-4 pt-4 border-t border-gray-100 space-y-2">
          {/* Disclaimer */}
          <div className="flex items-start gap-2 bg-orange-50 border border-orange-100 rounded-lg p-2.5 mb-3">
            <Info className="w-3.5 h-3.5 text-orange-500 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-orange-800">
              <strong>Advisory only.</strong> CVE data is sourced from the NVD. Applicability depends on exact firmware
              patch level and configuration. Verify with the vendor and obtain formal change approval before
              applying any firmware update.
            </p>
          </div>

          {state.cves.map(cve => (
            <div key={cve.cve_id} className="flex items-start gap-3 bg-gray-50 border border-gray-100 rounded-lg p-3">
              <div className="flex-shrink-0 pt-0.5">
                <span className={clsx(
                  'text-[10px] font-bold px-2 py-0.5 rounded border',
                  severityColor(cve.cvss_severity)
                )}>
                  {scoreLabel(cve.cvss_score, cve.cvss_severity)}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <a
                    href={cve.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-bold text-blue-600 hover:underline flex items-center gap-1"
                  >
                    {cve.cve_id} <ExternalLink className="w-3 h-3" />
                  </a>
                  {cve.published && (
                    <span className="text-[10px] text-gray-400">Published {cve.published.slice(0, 10)}</span>
                  )}
                </div>
                <p className="text-xs text-gray-600 leading-relaxed">{cve.description}</p>
              </div>
            </div>
          ))}

          {state.cves.length >= 10 && (
            <p className="text-xs text-gray-400 text-center pt-1">
              Showing top 10 CVEs ·{' '}
              <a
                href={`https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(device.vendor + ' ' + (device.os_version || ''))}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-500 hover:underline"
              >
                View all on NVD ↗
              </a>
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function Vulnerabilities() {
  const params = useParams<{ customerId?: string }>()
  const { activeCustomer } = useCustomer()
  const customerId = params.customerId || activeCustomer?.id

  const [devices, setDevices] = useState<FirewallDeviceT[]>([])
  const [loading, setLoading] = useState(true)
  const [vulnState, setVulnState] = useState<Record<string, DeviceVulnState>>({})

  // Load devices
  useEffect(() => {
    setLoading(true)
    getDevices(customerId)
      .then((data: FirewallDeviceT[]) => {
        const list = Array.isArray(data) ? data : []
        setDevices(list)
        // Initialize CVE state for devices. Check Point management API versions
        // are intentionally not treated as firewall OS versions.
        const initial: Record<string, DeviceVulnState> = {}
        list.forEach(d => {
          initial[d.id] = { status: 'idle', cves: [] }
        })
        setVulnState(initial)
      })
      .catch(() => setDevices([]))
      .finally(() => setLoading(false))
  }, [customerId])

  const loadVulns = async (deviceId: string, refresh = false) => {
    setVulnState(prev => ({ ...prev, [deviceId]: { ...prev[deviceId], status: 'loading' } }))
    try {
      const result = await getDeviceVulnerabilities(deviceId, refresh)
      setVulnState(prev => ({
        ...prev,
        [deviceId]: {
          status: 'done',
          cves: result.cves || [],
          error: result.error,
          cached: result.cached,
          os_version: result.os_version,
          queryable: result.queryable,
        },
      }))
    } catch {
      setVulnState(prev => ({
        ...prev,
        [deviceId]: { status: 'error', cves: [], error: 'Failed to load CVE data' },
      }))
    }
  }

  const loadAll = () => {
    devices
      .filter(d => displayOsVersion(d))
      .forEach(d => loadVulns(d.id))
  }

  // Aggregate counts
  const allCVEs = Object.values(vulnState).flatMap(s => s.cves)
  const critCount = allCVEs.filter(c => c.cvss_severity === 'CRITICAL').length
  const highCount = allCVEs.filter(c => c.cvss_severity === 'HIGH').length
  const medCount  = allCVEs.filter(c => c.cvss_severity === 'MEDIUM').length
  const checkedCount = Object.values(vulnState).filter(s => s.status === 'done').length
  const syncedDevices = devices.filter(d => displayOsVersion(d))

  return (
    <div>
      {/* Header */}
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Vulnerabilities</h1>
          <p className="page-subtitle">CVE exposure across all live firewall devices · NVD data source</p>
        </div>
        {syncedDevices.length > 0 && (
          <button onClick={loadAll} className="btn-secondary">
            <Shield className="w-4 h-4" />
            Check All Devices
          </button>
        )}
      </div>

      <div className="page-body max-w-5xl">

        {/* Summary bar */}
        {checkedCount > 0 && (
          <div className="grid grid-cols-4 gap-4 mb-6">
            {[
              { label: 'Devices Checked',  value: checkedCount,   color: 'text-blue-700',    bg: 'bg-blue-50' },
              { label: 'Critical CVEs',     value: critCount,      color: 'text-red-700',     bg: critCount > 0 ? 'bg-red-50' : 'bg-gray-50' },
              { label: 'High CVEs',         value: highCount,      color: 'text-orange-700',  bg: highCount > 0 ? 'bg-orange-50' : 'bg-gray-50' },
              { label: 'Medium CVEs',       value: medCount,       color: 'text-amber-700',   bg: medCount > 0 ? 'bg-amber-50' : 'bg-gray-50' },
            ].map(({ label, value, color, bg }) => (
              <div key={label} className={clsx('rounded-xl border border-transparent p-4 text-center', bg)}>
                <p className={clsx('text-2xl font-extrabold', color)}>{value}</p>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Advisory notice */}
        <div className="flex items-start gap-2 bg-blue-50 border border-blue-100 rounded-xl p-3.5 mb-5">
          <Info className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-blue-900">
            <strong>How this works:</strong> The OS version discovered during device sync is matched against
            the NIST National Vulnerability Database (NVD). Results are cached for 24 hours.
            CVEs are informational — confirm applicability with the vendor before planning any upgrade.
            <strong className="block mt-1">
              No firewall is modified. All recommendations require engineer validation and formal change approval.
            </strong>
          </div>
        </div>

        {/* Loading state */}
        {loading && (
          <div className="flex justify-center py-20">
            <div className="animate-spin w-9 h-9 border-b-2 border-blue-600 rounded-full" />
          </div>
        )}

        {/* No devices */}
        {!loading && devices.length === 0 && (
          <div className="card empty-state py-16">
            <Shield className="w-12 h-12 text-gray-200 mb-4" />
            <p className="text-lg font-semibold text-gray-500 mb-1">No devices configured</p>
            <p className="text-sm text-gray-400">
              Add live firewall devices and sync them to enable CVE checking.
            </p>
          </div>
        )}

        {/* No synced devices */}
        {!loading && devices.length > 0 && syncedDevices.length === 0 && (
          <div className="card empty-state py-12">
            <AlertTriangle className="w-10 h-10 text-amber-300 mb-3" />
            <p className="text-base font-semibold text-gray-500 mb-1">No devices have been synced yet</p>
            <p className="text-sm text-gray-400">
              Sync your devices to discover OS versions — CVE checking requires a known OS version.
            </p>
          </div>
        )}

        {/* Device list */}
        {!loading && devices.map(device => (
          <DeviceVulnRow
            key={device.id}
            device={device}
            state={vulnState[device.id] || { status: 'idle', cves: [] }}
            onLoad={() => loadVulns(device.id)}
            onRefresh={() => loadVulns(device.id, true)}
          />
        ))}
      </div>
    </div>
  )
}
