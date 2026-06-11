/**
 * Security Posture — unified tab page
 * =====================================
 * Merges Scorecard, Health Assessment, and Compliance into a single page
 * with a tab bar at the top. This reduces sidebar clutter from 3 nav items
 * down to 1 "Posture" entry while keeping all content accessible.
 *
 * SAFETY: Read-only. All child pages explicitly state that engineer
 * validation and change approval are required before any remediation.
 */
import { useSearchParams } from 'react-router-dom'
import { TrendingUp, Activity, CheckSquare } from 'lucide-react'
import { clsx } from 'clsx'
import { Scorecard } from './Scorecard'
import { HealthAssessment } from './HealthAssessment'
import { Compliance } from './Compliance'

type PostureTab = 'scorecard' | 'health' | 'compliance'

const TABS: { key: PostureTab; label: string; icon: React.ElementType; description: string }[] = [
  { key: 'scorecard',  label: 'Scorecard',     icon: TrendingUp,  description: 'Weighted hygiene score' },
  { key: 'health',     label: 'Health Check',  icon: Activity,    description: 'Config & attack surface' },
  { key: 'compliance', label: 'Compliance',    icon: CheckSquare, description: 'PCI-DSS · CIS · NIST · ISO' },
]

export function Posture() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = (searchParams.get('tab') as PostureTab) || 'scorecard'

  const setTab = (tab: PostureTab) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', tab)
    // Preserve policy_id if switching tabs
    setSearchParams(next, { replace: true })
  }

  return (
    <div>
      {/* Page header */}
      <div className="page-header sticky top-0 z-10">
        <div>
          <h1 className="page-title">Security Posture</h1>
          <p className="page-subtitle">Scorecard · Health Assessment · Compliance Checks</p>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 bg-gray-100 p-1 rounded-xl">
          {TABS.map(t => {
            const Icon = t.icon
            const active = activeTab === t.key
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-semibold transition-all',
                  active
                    ? 'bg-white text-blue-700 shadow-sm'
                    : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Tab content — all kept mounted to avoid re-loading data on tab switch */}
      <div className="page-body max-w-6xl">
        <div className={activeTab !== 'scorecard' ? 'hidden' : ''}>
          <Scorecard embedded />
        </div>
        <div className={activeTab !== 'health' ? 'hidden' : ''}>
          <HealthAssessment embedded />
        </div>
        <div className={activeTab !== 'compliance' ? 'hidden' : ''}>
          <Compliance embedded />
        </div>
      </div>
    </div>
  )
}
