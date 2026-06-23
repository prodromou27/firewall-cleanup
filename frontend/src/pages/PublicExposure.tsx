import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Shield, Globe, AlertTriangle, ArrowLeft, Download, Network } from 'lucide-react'
import { getPublicExposure, type PublicExposure } from '../api/client'
import { SeverityBadge } from '../components/ui/SeverityBadge'

export function PublicExposure() {
  const { policyId } = useParams<{ policyId: string }>()
  const [data, setData] = useState<PublicExposure | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!policyId) return
    setLoading(true)
    getPublicExposure(policyId)
      .then(setData)
      .catch(() => setError('Failed to load public exposure analysis.'))
      .finally(() => setLoading(false))
  }, [policyId])

  const exportJson = () => {
    if (!data) return
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `PublicExposure_${data.firewall_name || 'policy'}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  if (loading) return <div className="page-body"><div className="animate-spin w-7 h-7 border-b-2 border-brand-600 rounded-full mx-auto mt-16" /></div>
  if (error || !data) return <div className="page-body"><div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error || 'No data'}</div></div>

  return (
    <div>
      <div className="page-header">
        <div className="flex items-center gap-2">
          <Link to={`/policies/${policyId}`} className="text-gray-400 hover:text-gray-700"><ArrowLeft className="w-5 h-5" /></Link>
          <div>
            <h1 className="page-title flex items-center gap-2"><Globe className="w-5 h-5 text-brand-600" /> Public Exposure</h1>
            <p className="page-subtitle">{data.firewall_name} · {data.vendor} · read-only review</p>
          </div>
        </div>
        <button onClick={exportJson} className="btn-secondary flex items-center gap-1.5"><Download className="w-4 h-4" /> Export</button>
      </div>

      <div className="page-body space-y-4">
        {/* Risk summary */}
        <div className="grid sm:grid-cols-4 gap-3">
          <div className="card">
            <p className="text-xs text-gray-500">Exposure risk score</p>
            <p className="text-2xl font-bold">{data.risk_score}<span className="text-sm text-gray-400">/100</span></p>
          </div>
          <div className="card">
            <p className="text-xs text-gray-500">Public IPs</p>
            <p className="text-2xl font-bold">{data.public_ips.length}</p>
          </div>
          <div className="card">
            <p className="text-xs text-gray-500">Exposed ports</p>
            <p className="text-2xl font-bold">{data.exposed_ports.length}</p>
          </div>
          <div className="card">
            <p className="text-xs text-gray-500">Related findings</p>
            <p className="text-2xl font-bold">{data.findings.length}</p>
          </div>
        </div>

        {/* NAT availability gate */}
        {!data.nat_available && (
          <div className="card flex items-center gap-3 bg-amber-50 border-amber-200">
            <Network className="w-5 h-5 text-amber-500 flex-shrink-0" />
            <div>
              <p className="font-semibold text-amber-800">NAT Analysis Not Available</p>
              <p className="text-sm text-amber-700">No NAT data was captured for this policy, so NAT-specific checks (mappings, duplicates, overlaps) are skipped. Public exposure shown below is derived from the security policy only.</p>
            </div>
          </div>
        )}

        {/* Public interfaces */}
        <div className="card">
          <h3 className="font-semibold mb-2 flex items-center gap-1.5"><Network className="w-4 h-4 text-gray-400" /> Public Interfaces</h3>
          {!data.interfaces_available ? (
            <p className="text-sm text-gray-400">No interface data captured. Sync the device to discover interfaces.</p>
          ) : data.public_interfaces.length === 0 ? (
            <p className="text-sm text-gray-400">No public-facing interfaces detected.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {data.public_interfaces.map((i, n) => (
                <div key={n} className="border border-gray-100 rounded-lg px-3 py-1.5 text-sm">
                  <span className="font-semibold">{i.name}</span>
                  {i.ip && <span className="font-mono text-xs text-gray-500 ml-2">{i.ip}</span>}
                  {i.wan_facing && <span className="text-[10px] ml-2 px-1.5 py-0.5 rounded bg-info-50 text-info-600">WAN</span>}
                  {i.mgmt_access && <span className="text-[10px] ml-1 px-1.5 py-0.5 rounded bg-red-50 text-red-600">mgmt</span>}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Public IP inventory */}
        {data.public_ip_inventory.length > 0 && (
          <div className="card">
            <h3 className="font-semibold mb-2 flex items-center gap-1.5"><Globe className="w-4 h-4 text-gray-400" /> Public IP Inventory</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-gray-500 border-b">
                  <th className="py-1.5 pr-3">Public IP</th><th className="py-1.5 pr-3">Source</th>
                  <th className="py-1.5 pr-3">Reference</th><th className="py-1.5 pr-3">Mapped internal</th>
                  <th className="py-1.5 pr-3">Confidence</th>
                </tr></thead>
                <tbody>
                  {data.public_ip_inventory.map((r, n) => (
                    <tr key={n} className="border-b border-gray-50">
                      <td className="py-1.5 pr-3 font-mono text-xs">{r.public_ip}</td>
                      <td className="py-1.5 pr-3"><span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 capitalize">{r.source_type}</span></td>
                      <td className="py-1.5 pr-3 text-xs text-gray-500">{r.reference}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs">{r.mapped_internal || '—'}</td>
                      <td className="py-1.5 pr-3 text-xs">{r.confidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Published / exposed services */}
        <div className="card">
          <h3 className="font-semibold mb-2 flex items-center gap-1.5"><Shield className="w-4 h-4 text-gray-400" /> Published &amp; Exposed Services</h3>
          {data.exposures.length === 0 ? (
            <p className="text-sm text-gray-400">No public exposure detected.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-gray-500 border-b">
                  <th className="py-1.5 pr-3">Public IP / Source</th>
                  <th className="py-1.5 pr-3">Internal Target</th>
                  <th className="py-1.5 pr-3">Ports</th>
                  <th className="py-1.5 pr-3">Source</th>
                  <th className="py-1.5 pr-3">NAT rules</th>
                  <th className="py-1.5 pr-3">Security rules</th>
                </tr></thead>
                <tbody>
                  {data.exposures.map((e, i) => (
                    <tr key={i} className="border-b border-gray-50">
                      <td className="py-1.5 pr-3 font-mono text-xs">{e.public_ip}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs">{e.internal_target}</td>
                      <td className="py-1.5 pr-3">{e.service_any ? <span className="text-red-600 font-semibold">Any</span> : (e.ports.join(', ') || '—')}</td>
                      <td className="py-1.5 pr-3"><span className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 capitalize">{e.source}</span></td>
                      <td className="py-1.5 pr-3 text-xs text-gray-500">{e.nat_rules.join(', ') || '—'}</td>
                      <td className="py-1.5 pr-3 text-xs text-gray-500">{e.security_rules.join(', ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Related findings */}
        <div className="card">
          <h3 className="font-semibold mb-2 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4 text-gray-400" /> Related Findings</h3>
          {data.findings.length === 0 ? (
            <p className="text-sm text-gray-400">No NAT / public-exposure findings recorded for this policy.</p>
          ) : (
            <div className="space-y-1.5">
              {data.findings.map(f => (
                <div key={f.id} className="flex items-center gap-2 text-sm border-b border-gray-50 py-1">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="flex-1">{f.title}</span>
                  <span className="text-xs text-gray-400">{f.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <p className="text-xs text-gray-400">PolicyInsight is read-only. Findings support review and planning only; any change must go through the approved change-management process.</p>
      </div>
    </div>
  )
}
