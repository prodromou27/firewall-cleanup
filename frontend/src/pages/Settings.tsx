import { useEffect, useState } from 'react'
import {
  Settings as SettingsIcon, Shield, Activity, AlertTriangle, Network,
  Key, CheckCircle2, XCircle, RefreshCw, Server, Info, Bell,
} from 'lucide-react'
import { getSettings, updateSettings } from '../api/client'

const API_BASE = 'http://localhost:8000'
const API_KEY = 'yfm6ItUkxVVEmc78ijkyDmYSc53W8d657fPYXe7aB2c'

interface SettingsData {
  inactivity_threshold_low: number
  inactivity_threshold_medium: number
  inactivity_threshold_high: number
  risk_weights: Record<string, number>
  severity_thresholds: Record<string, number>
  temp_keywords: string[]
  risky_services: Array<{ name: string; protocol: string; port_start: number; port_end: number }>
  internal_networks: string[]
  webhook_url?: string
  webhook_events?: string[]
  webhook_events_available?: string[]
  nvd_api_key_set?: boolean
}

type Tab = 'overview' | 'thresholds' | 'services' | 'integrations' | 'api'

function SectionTitle({ icon: Icon, title, subtitle }: { icon: React.ElementType; title: string; subtitle?: string }) {
  return (
    <div className="flex items-center gap-3 mb-5">
      <div className="w-9 h-9 rounded-xl bg-blue-50 flex items-center justify-center">
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
      <span className="text-sm text-gray-600 w-40 flex-shrink-0">{label.replace(/_/g, ' ')}</span>
      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-sm font-bold text-gray-700 w-6 text-right">+{value}</span>
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
  // Integrations state
  const [webhookUrl, setWebhookUrl]         = useState('')
  const [webhookEvents, setWebhookEvents]   = useState<string[]>([])
  const [nvdApiKey, setNvdApiKey]           = useState('')
  const [savingInteg, setSavingInteg]       = useState(false)
  const [integSaved, setIntegSaved]         = useState(false)

  useEffect(() => {
    getSettings()
      .then(s => {
        const data = s as SettingsData
        setSettings(data)
        setWebhookUrl(data.webhook_url || '')
        setWebhookEvents(data.webhook_events || [])
      })
      .finally(() => setLoading(false))
  }, [])

  const checkApi = async () => {
    setApiChecking(true)
    try {
      const res = await fetch(`${API_BASE}/api/health`, {
        headers: { 'X-API-Key': API_KEY },
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
      await updateSettings({ webhook_url: webhookUrl, webhook_events: webhookEvents, nvd_api_key: nvdApiKey || undefined })
      setIntegSaved(true)
      setTimeout(() => setIntegSaved(false), 3000)
    } catch (e) { console.error(e) }
    finally { setSavingInteg(false) }
  }

  const toggleEvent = (evt: string) => {
    setWebhookEvents(prev => prev.includes(evt) ? prev.filter(e => e !== evt) : [...prev, evt])
  }

  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'overview',      label: 'Overview',       icon: SettingsIcon },
    { id: 'thresholds',    label: 'Risk & Scoring',  icon: Activity },
    { id: 'services',      label: 'Services',        icon: Network },
    { id: 'integrations',  label: 'Integrations',    icon: Bell },
    { id: 'api',           label: 'System',          icon: Server },
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

  return (
    <div>
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Analysis configuration, risk scoring, and system status</p>
        </div>
        <div className={`flex items-center gap-2 text-sm font-semibold px-3 py-1.5 rounded-lg ${
          apiStatus === 'ok' ? 'bg-emerald-50 text-emerald-700' :
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
        {/* Read-only notice */}
        <div className="flex items-start gap-3 bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6 text-sm text-blue-800">
          <Info className="w-4 h-4 flex-shrink-0 mt-0.5 text-blue-500" />
          <div>
            <strong>Read-only view.</strong> Settings are defined in <code className="bg-blue-100 px-1 rounded text-xs">backend/app/config.py</code> and can be overridden with environment variables.
            Live editing will be added in a future release.
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-100 p-1 rounded-xl mb-6 w-fit">
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
            </button>
          ))}
        </div>

        {/* ── Overview tab ── */}
        {activeTab === 'overview' && (
          <div className="space-y-5">
            {/* Inactivity thresholds */}
            <div className="card">
              <SectionTitle icon={Activity} title="Inactivity Thresholds" subtitle="Days without hits before a rule is flagged" />
              <div className="grid grid-cols-3 gap-4">
                {[
                  { key: 'inactivity_threshold_low',    label: 'Low',    color: 'text-blue-600',   bg: 'bg-blue-50',   ring: 'ring-blue-200' },
                  { key: 'inactivity_threshold_medium', label: 'Medium', color: 'text-amber-600',  bg: 'bg-amber-50',  ring: 'ring-amber-200' },
                  { key: 'inactivity_threshold_high',   label: 'High',   color: 'text-red-600',    bg: 'bg-red-50',    ring: 'ring-red-200' },
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
            </div>

            {/* Severity thresholds */}
            <div className="card">
              <SectionTitle icon={AlertTriangle} title="Severity Score Thresholds" subtitle="Minimum risk score to trigger each severity level" />
              <div className="grid grid-cols-3 gap-4">
                {[
                  { key: 'high',   label: 'High',   color: 'text-red-600',   bg: 'bg-red-50',   ring: 'ring-red-200' },
                  { key: 'medium', label: 'Medium', color: 'text-amber-600', bg: 'bg-amber-50', ring: 'ring-amber-200' },
                  { key: 'low',    label: 'Low',    color: 'text-blue-600',  bg: 'bg-blue-50',  ring: 'ring-blue-200' },
                ].map(({ key, label, color, bg, ring }) => (
                  <div key={key} className={`${bg} ring-1 ${ring} rounded-xl p-4 text-center`}>
                    <p className={`text-3xl font-extrabold ${color}`}>
                      {settings.severity_thresholds[key]}+
                    </p>
                    <p className="text-xs font-semibold text-gray-500 mt-1 uppercase tracking-wide">{label}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Temp keywords */}
            <div className="card">
              <SectionTitle icon={Shield} title="Temporary Rule Keywords" subtitle="Rules with these terms are flagged as temporary" />
              <div className="flex flex-wrap gap-2">
                {settings.temp_keywords.map(kw => (
                  <span key={kw} className="inline-flex items-center text-sm bg-amber-50 text-amber-700 ring-1 ring-amber-200 px-3 py-1 rounded-full font-mono font-medium">
                    {kw}
                  </span>
                ))}
              </div>
            </div>

            {/* Internal networks */}
            {settings.internal_networks?.length > 0 && (
              <div className="card">
                <SectionTitle icon={Network} title="Internal Network Ranges" subtitle="RFC-1918 and configured internal networks" />
                <div className="flex flex-wrap gap-2">
                  {settings.internal_networks.map(net => (
                    <span key={net} className="text-sm bg-gray-50 ring-1 ring-gray-200 text-gray-700 px-3 py-1 rounded-lg font-mono">
                      {net}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Risk & Scoring tab ── */}
        {activeTab === 'thresholds' && (
          <div className="card">
            <SectionTitle
              icon={Activity}
              title="Risk Score Weights"
              subtitle="Points added to a rule's risk score for each condition"
            />
            <div className="space-y-3">
              {Object.entries(settings.risk_weights)
                .sort((a, b) => b[1] - a[1])
                .map(([key, value]) => (
                  <RiskBar key={key} label={key} value={value} max={maxRiskWeight + 5} />
                ))}
            </div>
            <div className="mt-6 p-4 bg-gray-50 rounded-xl border border-gray-100 text-sm text-gray-600">
              <p className="font-semibold text-gray-800 mb-2">How risk scoring works</p>
              <ul className="space-y-1 text-xs">
                <li>• Each rule starts at 0. Conditions meeting thresholds add points.</li>
                <li>• A rule with source=any + service=any + zero hits = {(settings.risk_weights.any_source||0) + (settings.risk_weights.any_service||0) + (settings.risk_weights.no_hits_180d||0)} points.</li>
                <li>• Severity is then assigned based on the thresholds above.</li>
              </ul>
            </div>
          </div>
        )}

        {/* ── Services tab ── */}
        {activeTab === 'services' && (
          <div className="card">
            <SectionTitle icon={Network} title="Monitored Risky Services" subtitle={`${settings.risky_services.length} services flagged for review`} />
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Service Name</th>
                    <th>Protocol</th>
                    <th>Port Range</th>
                    <th>Risk Level</th>
                  </tr>
                </thead>
                <tbody>
                  {settings.risky_services.map(s => {
                    const isHighRisk = ['TELNET', 'FTP', 'RLOGIN', 'RSH', 'REXEC'].includes(s.name.toUpperCase())
                    return (
                      <tr key={s.name}>
                        <td>
                          <span className="font-semibold text-gray-900 font-mono">{s.name}</span>
                        </td>
                        <td>
                          <span className="text-xs uppercase font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-600">
                            {s.protocol}
                          </span>
                        </td>
                        <td className="font-mono text-sm text-gray-700">
                          {s.port_start === s.port_end ? s.port_start : `${s.port_start}–${s.port_end}`}
                        </td>
                        <td>
                          <span className={`badge ${isHighRisk ? 'badge-high' : 'badge-medium'}`}>
                            {isHighRisk ? 'High' : 'Medium'}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Integrations tab ── */}
        {activeTab === 'integrations' && (
          <div className="space-y-5">
            {/* Webhook */}
            <div className="card">
              <SectionTitle icon={Bell} title="Webhook Notifications" subtitle="Send event payloads to Slack, Teams, or any HTTP endpoint" />
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-gray-700 block mb-1.5">Webhook URL</label>
                  <input
                    type="url"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                    placeholder="https://hooks.slack.com/services/... or https://your-soc/webhook"
                    value={webhookUrl}
                    onChange={e => setWebhookUrl(e.target.value)}
                  />
                  <p className="text-xs text-gray-400 mt-1">Supports Slack incoming webhooks, MS Teams, and generic HTTP POST endpoints.</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700 block mb-2">Events to notify on</label>
                  <div className="space-y-2">
                    {(settings?.webhook_events_available || ['sync_completed', 'sync_error', 'high_finding']).map(evt => (
                      <label key={evt} className="flex items-center gap-3 p-2.5 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100">
                        <input
                          type="checkbox"
                          checked={webhookEvents.includes(evt)}
                          onChange={() => toggleEvent(evt)}
                          className="rounded"
                        />
                        <div>
                          <p className="text-sm font-medium text-gray-800">{evt.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</p>
                          <p className="text-xs text-gray-500">
                            {evt === 'sync_completed' && 'Fired after every successful live sync with rule/finding counts'}
                            {evt === 'sync_error'     && 'Fired when a live sync fails with error details'}
                            {evt === 'high_finding'   && 'Fired when analysis produces high-severity findings'}
                          </p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs text-gray-600">
                  <p className="font-semibold mb-1">Payload structure (JSON POST)</p>
                  <pre className="font-mono text-[10px] overflow-auto">{`{
  "event": "sync_completed",
  "timestamp": "2024-01-01T12:00:00Z",
  "platform": "PolicyLens",
  "data": { "device_name": "...", "finding_count": 12, ... }
}`}</pre>
                </div>
              </div>
            </div>

            {/* NVD API Key */}
            <div className="card">
              <SectionTitle icon={Shield} title="NIST NVD API Key" subtitle="Optional — increases CVE lookup rate limits from 5 to 50 req/30s" />
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  {settings?.nvd_api_key_set
                    ? <><CheckCircle2 className="w-4 h-4 text-green-500" /><span className="text-green-700 font-medium">NVD API key is configured</span></>
                    : <><Info className="w-4 h-4 text-amber-500" /><span className="text-amber-700">No NVD API key set — using unauthenticated access (5 req/30s)</span></>
                  }
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700 block mb-1.5">NVD API Key</label>
                  <input
                    type="password"
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none font-mono"
                    placeholder={settings?.nvd_api_key_set ? '••••••••••••••••' : 'Paste your NVD API key here'}
                    value={nvdApiKey}
                    onChange={e => setNvdApiKey(e.target.value)}
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Get a free key at <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener" className="text-blue-500 hover:underline">nvd.nist.gov/developers/request-an-api-key</a>.
                    Used only for CVE vulnerability lookups on the Device detail page.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={saveIntegrations}
                disabled={savingInteg}
                className="btn-primary flex items-center gap-2"
              >
                {savingInteg ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                {savingInteg ? 'Saving…' : 'Save Integration Settings'}
              </button>
              {integSaved && <span className="text-sm text-green-600 font-medium flex items-center gap-1"><CheckCircle2 className="w-4 h-4" /> Saved!</span>}
            </div>
          </div>
        )}

        {/* ── API / System tab ── */}
        {activeTab === 'api' && (
          <div className="space-y-5">
            <div className="card">
              <SectionTitle icon={Server} title="Backend API" subtitle="Connection status and endpoint configuration" />
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <p className="text-sm font-semibold text-gray-700">API Endpoint</p>
                    <p className="text-xs text-gray-400 font-mono mt-0.5">{API_BASE}</p>
                  </div>
                  <div className={`flex items-center gap-2 text-sm font-semibold px-3 py-1.5 rounded-lg ${
                    apiStatus === 'ok' ? 'bg-emerald-50 text-emerald-700' :
                    apiStatus === 'error' ? 'bg-red-50 text-red-700' :
                    'bg-gray-100 text-gray-500'
                  }`}>
                    {apiStatus === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    {apiStatus === 'ok' ? 'Connected' : 'Unreachable'}
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <p className="text-sm font-semibold text-gray-700">Authentication</p>
                    <p className="text-xs text-gray-400 mt-0.5">X-API-Key header · {API_KEY.slice(0, 8)}••••••••</p>
                  </div>
                  <span className="badge bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200">Active</span>
                </div>

                {apiVersion && (
                  <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="text-sm font-semibold text-gray-700">Backend Version</p>
                      <p className="text-xs text-gray-400 font-mono mt-0.5">{apiVersion}</p>
                    </div>
                  </div>
                )}

                <button
                  onClick={checkApi}
                  disabled={apiChecking}
                  className="btn-secondary w-full justify-center"
                >
                  <RefreshCw className={`w-4 h-4 ${apiChecking ? 'animate-spin' : ''}`} />
                  {apiChecking ? 'Testing connection…' : 'Test Connection'}
                </button>
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Shield} title="Security" subtitle="Platform security posture" />
              <div className="space-y-3">
                {[
                  { label: 'Read-Only Analysis Mode',      ok: true,  desc: 'No firewall rules are modified by this platform' },
                  { label: 'Encrypted credentials at rest',ok: true,  desc: 'Fernet symmetric encryption for stored secrets' },
                  { label: 'API key authentication',        ok: true,  desc: 'All API calls require X-API-Key header' },
                  { label: 'Change approval disclaimer',    ok: true,  desc: 'All recommendations display engineer review notice' },
                ].map(item => (
                  <div key={item.label} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-semibold text-gray-800">{item.label}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="card">
              <SectionTitle icon={Info} title="About PolicyLens" />
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">Platform</p>
                  <p className="font-semibold text-gray-800">PolicyLens</p>
                  <p className="text-xs text-gray-500">Firewall Audit Platform</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">Version</p>
                  <p className="font-semibold text-gray-800 font-mono">v2.1.0</p>
                  <p className="text-xs text-gray-500">Frontend</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">Stack</p>
                  <p className="font-semibold text-gray-800">React 18 + FastAPI</p>
                  <p className="text-xs text-gray-500">TypeScript · SQLite · Python</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-400 font-medium uppercase tracking-wide mb-1">Mode</p>
                  <p className="font-semibold text-emerald-700">Read-Only Analysis</p>
                  <p className="text-xs text-gray-500">No firewall modifications</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
