import { useEffect, useState } from 'react'
import {
  Settings as SettingsIcon, Shield, Activity, AlertTriangle, Network,
  CheckCircle2, XCircle, RefreshCw, Server, Info, Bell,
  Lock, Download, Upload, Database, Key,
  AlertOctagon,
} from 'lucide-react'
import { getSettings, updateSettings, API_BASE, API_KEY } from '../api/client'

interface SettingsData {
  inactivity_threshold_low: number
  inactivity_threshold_medium: number
  inactivity_threshold_high: number
  risk_weights: Record<string, number>
  severity_thresholds: { high: number; medium: number; low: number }
  temp_keywords: string[]
  risky_services: Array<{ name: string; protocol: string; port_start: number; port_end: number }>
  internal_networks: string[]
  webhook_url?: string
  webhook_events?: string[]
  webhook_events_available?: string[]
  nvd_api_key_set?: boolean
  syslog_listener?: { active: boolean; port: number; cooldown_seconds?: number }
  security?: { auth_enabled: boolean; secret_key_set: boolean; api_key_prefix: string | null }
  app_version?: string
}

type Tab = 'overview' | 'thresholds' | 'services' | 'integrations' | 'security' | 'backup'

function SectionTitle({ icon: Icon, title, subtitle }: { icon: React.ElementType; title: string; subtitle?: string }) {
  return (
    <div className="flex items-center gap-3 mb-5">
      <div className="w-9 h-9 rounded-xl bg-blue-50 flex items-center justify-center flex-shrink-0">
        <Icon className="w-5 h-5 text-blue-600" />
      </div>
      <div>
        <h2 className="text-base font-bold text-gray-900">{title}</h2>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  )
}

function RiskBar({ label, value, max = 30 }: { label: string; value: number; max?: number }) {
  const pct = Math.min(100, (value / max) * 100)
  const color = value >= 20 ? 'bg-red-500' : value >= 10 ? 'bg-amber-500' : 'bg-blue-500'
  return (
    <div className="flex items-center gap-3">
      <span className="text-sm text-gray-600 w-44 flex-shrink-0 capitalize">{label.replace(/_/g, ' ')}</span>
      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-sm font-bold text-gray-700 w-8 text-right">+{value}</span>
    </div>
  )
}

function StatusRow({ label, ok, warn, desc }: { label: string; ok?: boolean; warn?: boolean; desc: string }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
      {ok
        ? <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
        : warn
        ? <AlertOctagon className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
        : <XCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
      }
      <div>
        <p className="text-sm font-semibold text-gray-800">{label}</p>
        <p className="text-xs text-gray-500 mt-0.5">{desc}</p>
      </div>
    </div>
  )
}

export function Settings() {
  const [settings, setSettings] = useState<SettingsData | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [apiStatus, setApiStatus] = useState<'unknown' | 'ok' | 'error'>('unknown')
  const [apiChecking, setApiChecking] = useState(false)
  const [apiVersion, setApiVersion] = useState('')

  // Integrations
  const [webhookUrl, setWebhookUrl]       = useState('')
  const [webhookEvents, setWebhookEvents] = useState<string[]>([])
  const [nvdApiKey, setNvdApiKey]         = useState('')
  const [savingInteg, setSavingInteg]     = useState(false)
  const [integSaved, setIntegSaved]       = useState(false)

  // Editable thresholds
  const [threshLow,    setThreshLow]    = useState(0)
  const [threshMedium, setThreshMedium] = useState(0)
  const [threshHigh,   setThreshHigh]   = useState(0)
  const [sevHigh,      setSevHigh]      = useState(0)
  const [sevMedium,    setSevMedium]    = useState(0)
  const [sevLow,       setSevLow]       = useState(0)
  const [savingThresh, setSavingThresh] = useState(false)
  const [threshSaved,  setThreshSaved]  = useState(false)

  // Backup
  const [backupStatus, setBackupStatus] = useState<string | null>(null)

  const load = () => {
    getSettings()
      .then(s => {
        const data = s as SettingsData
        setSettings(data)
        setWebhookUrl(data.webhook_url || '')
        setWebhookEvents(data.webhook_events || [])
        setThreshLow(data.inactivity_threshold_low)
        setThreshMedium(data.inactivity_threshold_medium)
        setThreshHigh(data.inactivity_threshold_high)
        setSevHigh(data.severity_thresholds.high)
        setSevMedium(data.severity_thresholds.medium)
        setSevLow(data.severity_thresholds.low)
      })
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const checkApi = async () => {
    setApiChecking(true)
    try {
      const res = await fetch(`${API_BASE}/api/health`, {
        headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
      })
      if (res.ok) {
        const data = await res.json()
        setApiVersion(data.version || '')
        setApiStatus('ok')
      } else {
        setApiStatus('error')
      }
    } catch {
      setApiStatus('error')
    } finally {
      setApiChecking(false)
    }
  }

  useEffect(() => { checkApi() }, [])

  const saveIntegrations = async () => {
    setSavingInteg(true)
    try {
      await updateSettings({
        webhook_url: webhookUrl,
        webhook_events: webhookEvents,
        nvd_api_key: nvdApiKey || undefined,
      })
      setIntegSaved(true)
      setTimeout(() => setIntegSaved(false), 3000)
      load()
    } catch (e) { console.error(e) }
    finally { setSavingInteg(false) }
  }

  const saveThresholds = async () => {
    setSavingThresh(true)
    try {
      await updateSettings({
        inactivity_threshold_low:    threshLow,
        inactivity_threshold_medium: threshMedium,
        inactivity_threshold_high:   threshHigh,
        severity_high_threshold:     sevHigh,
        severity_medium_threshold:   sevMedium,
        severity_low_threshold:      sevLow,
      })
      setThreshSaved(true)
      setTimeout(() => setThreshSaved(false), 3000)
      load()
    } catch (e) { console.error(e) }
    finally { setSavingThresh(false) }
  }

  const toggleEvent = (evt: string) =>
    setWebhookEvents(prev => prev.includes(evt) ? prev.filter(e => e !== evt) : [...prev, evt])

  const downloadBackup = async (type: 'database' | 'settings') => {
    setBackupStatus(`Preparing ${type} backup…`)
    try {
      const res = await fetch(`${API_BASE}/api/settings/backup/${type}`, {
        headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setBackupStatus(`Error: ${err.detail || res.statusText}`)
        setTimeout(() => setBackupStatus(null), 5000)
        return
      }
      const cd = res.headers.get('content-disposition') || ''
      const name = cd.match(/filename="?([^";]+)"?/)?.[1] || `backup_${type}.${type === 'database' ? 'db' : 'json'}`
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = name; a.click()
      URL.revokeObjectURL(url)
      setBackupStatus(`✓ ${name} downloaded`)
      setTimeout(() => setBackupStatus(null), 4000)
    } catch (e) {
      setBackupStatus('Download failed — check console')
      setTimeout(() => setBackupStatus(null), 5000)
    }
  }

  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'overview',     label: 'Overview',       icon: SettingsIcon },
    { id: 'thresholds',   label: 'Risk & Scoring',  icon: Activity },
    { id: 'services',     label: 'Services',        icon: Network },
    { id: 'integrations', label: 'Integrations',    icon: Bell },
    { id: 'security',     label: 'Security',        icon: Lock },
    { id: 'backup',       label: 'Backup',          icon: Database },
  ]

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-b-2 border-blue-600 rounded-full" />
      </div>
    )
  }

  if (!settings) return <div className="p-8 text-red-600">Failed to load settings.</div>

  const maxRiskWeight = Math.max(...Object.values(settings.risk_weights))
  const sec = settings.security

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Analysis configuration, risk scoring, and system status</p>
        </div>
        <div className={`flex items-center gap-2 text-sm font-semibold px-3 py-1.5 rounded-lg ${
          apiStatus === 'ok'    ? 'bg-emerald-50 text-emerald-700' :
          apiStatus === 'error' ? 'bg-red-50 text-red-700' :
          'bg-gray-50 text-gray-500'
        }`}>
          {apiStatus === 'ok'
            ? <CheckCircle2 className="w-4 h-4" />
            : apiStatus === 'error'
            ? <XCircle className="w-4 h-4" />
            : <RefreshCw className="w-4 h-4 animate-spin" />}
          {apiStatus === 'ok' ? `Backend connected${apiVersion ? ` · v${apiVersion}` : ''}` :
           apiStatus === 'error' ? 'Backend unreachable' : 'Checking…'}
        </div>
      </div>

      <div className="page-body">
        {/* Tabs */}
        <div className="flex flex-wrap gap-1 bg-gray-100 p-1 rounded-xl mb-6 w-fit">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                activeTab === t.id
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <t.icon className="w-4 h-4" />
              {t.label}
              {t.id === 'security' && sec && !sec.auth_enabled && (
                <span className="ml-0.5 w-2 h-2 rounded-full bg-red-500 inline-block" />
              )}
            </button>
          ))}
        </div>

        {/* ── Overview ── */}
        {activeTab === 'overview' && (
          <div className="space-y-5">
            <div className="card">
              <SectionTitle icon={Activity} title="Inactivity Thresholds" subtitle="Days without hits before a rule is flagged" />
              <div className="grid grid-cols-3 gap-4">
                {[
                  { key: 'inactivity_threshold_low',    label: 'Low',    color: 'text-blue-600',  bg: 'bg-blue-50',  ring: 'ring-blue-200' },
                  { key: 'inactivity_threshold_medium', label: 'Medium', color: 'text-amber-600', bg: 'bg-amber-50', ring: 'ring-amber-200' },
                  { key: 'inactivity_threshold_high',   label: 'High',   color: 'text-red-600',   bg: 'bg-red-50',   ring: 'ring-red-200' },
                ].map(({ key, label, color, bg, ring }) => (
                  <div key={key} className={`${bg} ring-1 ${ring} rounded-xl p-4 text-center`}>
                    <p className={`text-3xl font-extrabold ${color}`}>
                      {(settings as unknown as Record<string, number>)[key]}
                    </p>
                    <p className="text-xs font-semibold text-gray-500 mt-1 uppercase tracking-wide">{label} threshold</p>
                    <p className="text-[10px] text-gray-400 mt-0.5">days</p>
                  </div>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-3">Edit these values in the <button className="text-blue-500 hover:underline" onClick={() => setActiveTab('thresholds')}>Risk &amp; Scoring</button> tab.</p>
            </div>

            <div className="card">
              <SectionTitle icon={AlertTriangle} title="Severity Score Thresholds" subtitle="Minimum risk score to trigger each severity level" />
              <div className="grid grid-cols-3 gap-4">
                {[
                  { key: 'high',   label: 'High',   color: 'text-red-600',   bg: 'bg-red-50',   ring: 'ring-red-200' },
                  { key: 'medium', label: 'Medium', color: 'text-amber-600', bg: 'bg-amber-50', ring: 'ring-amber-200' },
                  { key: 'low',    label: 'Low',    color: 'text-blue-600',  bg: 'bg-blue-50',  ring: 'ring-blue-200' },
                ].map(({ key, label, color, bg, ring }) => (
                  <div key={key} className={`${bg} ring-1 ${ring} rounded-xl p-4 text-center`}>
                    <p className={`text-3xl font-extrabold ${color}`}>{settings.severity_thresholds[key as keyof typeof settings.severity_thresholds]}+</p>
                    <p className="text-xs font-semibold text-gray-500 mt-1 uppercase tracking-wide">{label}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Shield} title="Temporary Rule Keywords" subtitle="Rules with these terms are flagged as temporary" />
              <div className="flex flex-wrap gap-2">
                {settings.temp_keywords.map(kw => (
                  <span key={kw} className="text-sm bg-amber-50 text-amber-700 ring-1 ring-amber-200 px-3 py-1 rounded-full font-mono font-medium">{kw}</span>
                ))}
              </div>
            </div>

            {settings.internal_networks?.length > 0 && (
              <div className="card">
                <SectionTitle icon={Network} title="Internal Network Ranges" subtitle="RFC-1918 and configured internal networks" />
                <div className="flex flex-wrap gap-2">
                  {settings.internal_networks.map(net => (
                    <span key={net} className="text-sm bg-gray-50 ring-1 ring-gray-200 text-gray-700 px-3 py-1 rounded-lg font-mono">{net}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Risk & Scoring ── */}
        {activeTab === 'thresholds' && (
          <div className="space-y-5">
            <div className="card">
              <SectionTitle icon={Activity} title="Risk Score Weights" subtitle="Points added to a rule's risk score for each condition (read-only — set in config.py)" />
              <div className="space-y-3">
                {Object.entries(settings.risk_weights)
                  .sort((a, b) => b[1] - a[1])
                  .map(([key, value]) => (
                    <RiskBar key={key} label={key} value={value} max={maxRiskWeight + 5} />
                  ))}
              </div>
            </div>

            {/* Editable thresholds */}
            <div className="card">
              <SectionTitle icon={AlertTriangle} title="Inactivity Thresholds" subtitle="Override how many days without hits trigger each finding severity" />
              <div className="grid grid-cols-3 gap-4 mb-5">
                {[
                  { label: 'Low threshold (days)',    val: threshLow,    set: setThreshLow,    color: 'border-blue-300 focus:ring-blue-400' },
                  { label: 'Medium threshold (days)', val: threshMedium, set: setThreshMedium, color: 'border-amber-300 focus:ring-amber-400' },
                  { label: 'High threshold (days)',   val: threshHigh,   set: setThreshHigh,   color: 'border-red-300 focus:ring-red-400' },
                ].map(({ label, val, set, color }) => (
                  <div key={label}>
                    <label className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1.5 block">{label}</label>
                    <input
                      type="number" min={1}
                      value={val}
                      onChange={e => set(parseInt(e.target.value) || 0)}
                      className={`w-full border rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 outline-none ${color}`}
                    />
                  </div>
                ))}
              </div>

              <SectionTitle icon={AlertOctagon} title="Severity Score Thresholds" subtitle="Minimum risk score to assign a severity level" />
              <div className="grid grid-cols-3 gap-4 mb-5">
                {[
                  { label: 'High (min score)',   val: sevHigh,   set: setSevHigh,   color: 'border-red-300 focus:ring-red-400' },
                  { label: 'Medium (min score)', val: sevMedium, set: setSevMedium, color: 'border-amber-300 focus:ring-amber-400' },
                  { label: 'Low (min score)',    val: sevLow,    set: setSevLow,    color: 'border-blue-300 focus:ring-blue-400' },
                ].map(({ label, val, set, color }) => (
                  <div key={label}>
                    <label className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1.5 block">{label}</label>
                    <input
                      type="number" min={0}
                      value={val}
                      onChange={e => set(parseInt(e.target.value) || 0)}
                      className={`w-full border rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 outline-none ${color}`}
                    />
                  </div>
                ))}
              </div>

              <div className="flex items-center gap-3">
                <button onClick={saveThresholds} disabled={savingThresh} className="btn-primary flex items-center gap-2">
                  {savingThresh ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                  {savingThresh ? 'Saving…' : 'Save Thresholds'}
                </button>
                {threshSaved && <span className="text-sm text-green-600 font-medium flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Saved!</span>}
              </div>
            </div>
          </div>
        )}

        {/* ── Services ── */}
        {activeTab === 'services' && (
          <div className="card">
            <SectionTitle icon={Network} title="Monitored Risky Services" subtitle={`${settings.risky_services.length} services flagged for review`} />
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>Service Name</th><th>Protocol</th><th>Port Range</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                  {settings.risky_services.map(s => {
                    const isHighRisk = ['TELNET', 'FTP', 'RLOGIN', 'RSH', 'REXEC'].includes(s.name.toUpperCase())
                    return (
                      <tr key={s.name}>
                        <td><span className="font-semibold text-gray-900 font-mono">{s.name}</span></td>
                        <td><span className="text-xs uppercase font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600">{s.protocol}</span></td>
                        <td className="font-mono text-sm text-gray-700">{s.port_start === s.port_end ? s.port_start : `${s.port_start}–${s.port_end}`}</td>
                        <td><span className={`badge ${isHighRisk ? 'badge-high' : 'badge-medium'}`}>{isHighRisk ? 'High' : 'Medium'}</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Integrations ── */}
        {activeTab === 'integrations' && (
          <div className="space-y-5">
            <div className="card">
              <SectionTitle icon={Bell} title="Webhook Notifications" subtitle="Send event payloads to Slack, Teams, or any HTTP endpoint" />
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-gray-700 block mb-1.5">Webhook URL</label>
                  <input
                    type="url"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                    placeholder="https://hooks.slack.com/services/…"
                    value={webhookUrl}
                    onChange={e => setWebhookUrl(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700 block mb-2">Events to notify on</label>
                  <div className="space-y-2">
                    {(settings.webhook_events_available || ['sync_completed', 'sync_error', 'high_finding']).map(evt => (
                      <label key={evt} className="flex items-center gap-3 p-2.5 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100">
                        <input type="checkbox" checked={webhookEvents.includes(evt)} onChange={() => toggleEvent(evt)} className="rounded" />
                        <div>
                          <p className="text-sm font-medium text-gray-800">{evt.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</p>
                          <p className="text-xs text-gray-500">
                            {evt === 'sync_completed' && 'Fired after every successful live sync'}
                            {evt === 'sync_error'     && 'Fired when a live sync fails'}
                            {evt === 'high_finding'   && 'Fired when analysis produces high-severity findings'}
                          </p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Shield} title="NIST NVD API Key" subtitle="Optional — increases CVE lookup rate limits from 5 to 50 req/30s" />
              <div className="flex items-center gap-2 text-sm mb-3">
                {settings.nvd_api_key_set
                  ? <><CheckCircle2 className="w-4 h-4 text-green-500" /><span className="text-green-700 font-medium">NVD API key is configured</span></>
                  : <><Info className="w-4 h-4 text-amber-500" /><span className="text-amber-700">No NVD API key — unauthenticated (5 req/30s)</span></>
                }
              </div>
              <input
                type="password"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                placeholder={settings.nvd_api_key_set ? '••••••••••••••••' : 'Paste NVD API key'}
                value={nvdApiKey}
                onChange={e => setNvdApiKey(e.target.value)}
              />
              <p className="text-xs text-gray-400 mt-1">
                Get a free key at{' '}
                <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener" className="text-blue-500 hover:underline">nvd.nist.gov</a>.
              </p>
            </div>

            {settings.syslog_listener && (
              <div className="card">
                <SectionTitle icon={Bell} title="Real-Time Syslog Monitoring" subtitle="Receives device syslogs and triggers immediate re-sync" />
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <p className="text-sm font-semibold text-gray-700">Listener Status</p>
                    <p className="text-xs text-gray-400 mt-0.5">UDP port {settings.syslog_listener.port}</p>
                  </div>
                  <span className={`badge ${settings.syslog_listener.active ? 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200' : 'bg-amber-50 text-amber-700 ring-1 ring-amber-200'}`}>
                    {settings.syslog_listener.active ? '● Active' : '○ Inactive'}
                  </span>
                </div>
              </div>
            )}

            <div className="flex items-center gap-3">
              <button onClick={saveIntegrations} disabled={savingInteg} className="btn-primary flex items-center gap-2">
                {savingInteg ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                {savingInteg ? 'Saving…' : 'Save Integration Settings'}
              </button>
              {integSaved && <span className="text-sm text-green-600 font-medium flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Saved!</span>}
            </div>
          </div>
        )}

        {/* ── Security ── */}
        {activeTab === 'security' && (
          <div className="space-y-5">
            {/* Live auth status from backend */}
            <div className="card">
              <SectionTitle icon={Lock} title="Authentication & Access Control" subtitle="Live status from backend configuration" />
              <div className="space-y-3">
                <StatusRow
                  label="API Key Authentication"
                  ok={sec?.auth_enabled}
                  warn={!sec?.auth_enabled}
                  desc={sec?.auth_enabled
                    ? `Enabled — key prefix: ${sec.api_key_prefix ?? '(set)'}`
                    : 'DISABLED — API_KEY not set in .env. Any request is accepted. Set API_KEY before exposing on a network.'}
                />
                <StatusRow
                  label="Credential Encryption Key"
                  ok={sec?.secret_key_set}
                  warn={!sec?.secret_key_set}
                  desc={sec?.secret_key_set
                    ? 'SECRET_KEY is configured — device credentials encrypted with Fernet'
                    : 'SECRET_KEY not set — credentials are encrypted with a dev fallback key. Set SECRET_KEY in .env for production.'}
                />
                <StatusRow
                  label="Read-Only Analysis Mode"
                  ok
                  desc="This platform never modifies, deletes, or reorders firewall rules. All recommendations require engineer review and formal change approval."
                />
                <StatusRow
                  label="Tenant Data Isolation"
                  ok
                  desc="All data access is scoped per customer. Cross-tenant reads and mutations are rejected at the API layer."
                />
                <StatusRow
                  label="Encrypted Credentials at Rest"
                  ok
                  desc="Device credentials (SSH passwords, API tokens) are stored encrypted using Fernet symmetric encryption."
                />
                <StatusRow
                  label="Security Headers"
                  ok
                  desc="X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and X-XSS-Protection headers are set on all responses."
                />
              </div>
            </div>

            {(!sec?.auth_enabled || !sec?.secret_key_set) && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertOctagon className="w-5 h-5 text-red-600 flex-shrink-0" />
                  <p className="font-semibold text-red-800">Action required before production deployment</p>
                </div>
                <ul className="text-sm text-red-700 space-y-1 pl-7 list-disc">
                  {!sec?.auth_enabled && <li>Set <code className="bg-red-100 px-1 rounded font-mono text-xs">API_KEY=&lt;strong-random-key&gt;</code> in <code className="bg-red-100 px-1 rounded font-mono text-xs">backend/.env</code></li>}
                  {!sec?.secret_key_set && <li>Set <code className="bg-red-100 px-1 rounded font-mono text-xs">SECRET_KEY=&lt;32-byte-base64-key&gt;</code> in <code className="bg-red-100 px-1 rounded font-mono text-xs">backend/.env</code></li>}
                </ul>
              </div>
            )}

            <div className="card">
              <SectionTitle icon={Server} title="Backend Connection" />
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <p className="text-sm font-semibold text-gray-700">API Status</p>
                    <p className="text-xs text-gray-400 mt-0.5">Backend health check</p>
                  </div>
                  <div className={`flex items-center gap-2 text-sm font-semibold px-3 py-1.5 rounded-lg ${
                    apiStatus === 'ok' ? 'bg-emerald-50 text-emerald-700' :
                    apiStatus === 'error' ? 'bg-red-50 text-red-700' : 'bg-gray-100 text-gray-500'
                  }`}>
                    {apiStatus === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    {apiStatus === 'ok' ? `Connected · v${apiVersion}` : 'Unreachable'}
                  </div>
                </div>
                <button onClick={checkApi} disabled={apiChecking} className="btn-secondary w-full justify-center">
                  <RefreshCw className={`w-4 h-4 ${apiChecking ? 'animate-spin' : ''}`} />
                  {apiChecking ? 'Testing…' : 'Test Connection'}
                </button>
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Info} title="About PolicyInsight" />
              <div className="grid grid-cols-2 gap-3 text-sm">
                {[
                  { label: 'Platform',  value: 'PolicyInsight',           sub: 'Firewall Audit Platform' },
                  { label: 'Version',   value: `v${settings.app_version || '2.1.0'}`, sub: 'Backend + Frontend' },
                  { label: 'Stack',     value: 'React 18 + FastAPI',   sub: 'TypeScript · SQLite · Python' },
                  { label: 'Mode',      value: 'Read-Only Analysis',   sub: 'No firewall modifications' },
                ].map(item => (
                  <div key={item.label} className="p-3 bg-gray-50 rounded-lg">
                    <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">{item.label}</p>
                    <p className="font-semibold text-gray-800">{item.value}</p>
                    <p className="text-xs text-gray-500">{item.sub}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Backup ── */}
        {activeTab === 'backup' && (
          <div className="space-y-5">
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-800 flex items-start gap-3">
              <Info className="w-4 h-4 flex-shrink-0 mt-0.5 text-blue-500" />
              <div>
                <strong>Backup recommendation:</strong> Schedule regular database backups, especially before upgrades.
                The SQLite database contains all policies, findings, devices, and customers.
                Store backups in a separate location from the server.
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Database} title="Database Backup" subtitle="Download a complete copy of the SQLite database" />
              <div className="space-y-4">
                <div className="p-4 bg-gray-50 rounded-xl border border-gray-100">
                  <div className="flex items-center gap-3 mb-2">
                    <Database className="w-5 h-5 text-gray-500" />
                    <div>
                      <p className="text-sm font-semibold text-gray-800">policyinsight.db</p>
                      <p className="text-xs text-gray-500">All customers, policies, findings, devices, rules, objects</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-400">
                    The database is copied to a temporary file before download to avoid read contention.
                    Safe to download while the application is running.
                  </p>
                </div>
                <button
                  onClick={() => downloadBackup('database')}
                  className="btn-primary flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download Database Backup (.db)
                </button>
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Key} title="Settings Backup" subtitle="Export all saved settings (webhooks, API keys, thresholds) as JSON" />
              <div className="space-y-4">
                <p className="text-sm text-gray-600">
                  Exports all database-stored setting overrides. Use this to migrate settings to a new instance or
                  restore after a fresh installation.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => downloadBackup('settings')}
                    className="btn-secondary flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Export Settings JSON
                  </button>
                </div>
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Upload} title="Restore Settings" subtitle="Upload a previously exported settings JSON to restore configuration" />
              <div className="space-y-3">
                <p className="text-xs text-amber-700 bg-amber-50 rounded-lg px-3 py-2 border border-amber-200">
                  ⚠ Restoring will overwrite current webhook URL, NVD API key, and threshold overrides with the values from the file.
                  The database itself is NOT affected — only application settings.
                </p>
                <input
                  type="file"
                  accept=".json"
                  className="block w-full text-sm text-gray-500 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 cursor-pointer"
                  onChange={async e => {
                    const file = e.target.files?.[0]
                    if (!file) return
                    try {
                      const text = await file.text()
                      const payload = JSON.parse(text)
                      const res = await fetch(`${API_BASE}/api/settings/backup/settings/restore`, {
                        method: 'POST',
                        headers: {
                          'Content-Type': 'application/json',
                          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
                        },
                        body: JSON.stringify(payload),
                      })
                      const data = await res.json()
                      setBackupStatus(res.ok ? `✓ Restored ${data.restored} settings entries` : `Error: ${data.detail}`)
                      if (res.ok) load()
                      setTimeout(() => setBackupStatus(null), 5000)
                    } catch {
                      setBackupStatus('Failed to parse file')
                      setTimeout(() => setBackupStatus(null), 5000)
                    }
                    e.target.value = ''
                  }}
                />
              </div>
            </div>

            {backupStatus && (
              <div className={`flex items-center gap-2 p-3 rounded-xl text-sm font-medium border ${
                backupStatus.startsWith('✓')
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-red-50 text-red-700 border-red-200'
              }`}>
                {backupStatus.startsWith('✓') ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                {backupStatus}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
