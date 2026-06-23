import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { Layout } from './components/Layout'
import { CustomerProvider } from './contexts/CustomerContext'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Upload } from './pages/Upload'
import { Policies, PolicyDetail } from './pages/Policies'
import { Findings } from './pages/Findings'
import { Rulebase } from './pages/Rulebase'
import { PublicExposure } from './pages/PublicExposure'
import { Objects } from './pages/Objects'
import { ReportsDashboard } from './pages/reporting/ReportsDashboard'
import { ReportBuilder } from './pages/reporting/ReportBuilder'
import { TemplateManager } from './pages/reporting/TemplateManager'
import { TemplateEditor } from './pages/reporting/TemplateEditor'
import { Scorecard } from './pages/Scorecard'
import { HealthAssessment } from './pages/HealthAssessment'
import { Posture } from './pages/Posture'
import { Vulnerabilities } from './pages/Vulnerabilities'
import { Settings } from './pages/Settings'
import { Customers } from './pages/Customers'
import { CustomerDetail } from './pages/CustomerDetail'
import { Devices } from './pages/Devices'
import { DeviceHistory } from './pages/DeviceHistory'
import { PolicyComparison } from './pages/PolicyComparison'
import { Compliance } from './pages/Compliance'
import { AuditLog } from './pages/AuditLog'
import { CleanupPlan } from './pages/CleanupPlan'
import { ChangeWatch } from './pages/ChangeWatch'

function AuthenticatedApp() {
  return (
    <CustomerProvider>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Layout>
          <Routes>
            {/* Global routes — data is scoped by global CustomerContext */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyDetail />} />
            <Route path="/policies/:policyId/rules" element={<Rulebase />} />
            <Route path="/policies/:policyId/public-exposure" element={<PublicExposure />} />
            <Route path="/policies/:policyId/compare" element={<PolicyComparison />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/objects" element={<Objects />} />
            <Route path="/reports" element={<ReportsDashboard />} />
            <Route path="/reports/new" element={<ReportBuilder />} />
            <Route path="/reports/templates" element={<TemplateManager />} />
            <Route path="/reports/templates/:id" element={<TemplateEditor />} />
            <Route path="/posture" element={<Posture />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/scorecard" element={<Scorecard />} />
            <Route path="/health" element={<HealthAssessment />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/cleanup-plan" element={<CleanupPlan />} />
            <Route path="/changes" element={<ChangeWatch />} />

            {/* Customer management */}
            <Route path="/customers" element={<Customers />} />
            <Route path="/customers/:customerId" element={<CustomerDetail />} />

            {/* Device history still needs both IDs in URL */}
            <Route path="/customers/:customerId/devices/:deviceId/history" element={<DeviceHistory />} />

            {/* Legacy customer-scoped routes — kept so old bookmarks still work */}
            <Route path="/customers/:customerId/devices" element={<Devices />} />
            <Route path="/customers/:customerId/policies" element={<Policies />} />
            <Route path="/customers/:customerId/policies/:id" element={<PolicyDetail />} />
            <Route path="/customers/:customerId/findings" element={<Findings />} />
            <Route path="/customers/:customerId/objects" element={<Objects />} />
            <Route path="/customers/:customerId/reports" element={<ReportsDashboard />} />
            <Route path="/customers/:customerId/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/customers/:customerId/posture" element={<Posture />} />
            <Route path="/customers/:customerId/compliance" element={<Compliance />} />
            <Route path="/customers/:customerId/scorecard" element={<Scorecard />} />
            <Route path="/customers/:customerId/health" element={<HealthAssessment />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </CustomerProvider>
  )
}

function Gate() {
  const { user, loading } = useAuth()
  if (loading) {
    return (
      <div className="auth-shell flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-brand-300 animate-spin" />
      </div>
    )
  }
  if (!user) return <Login />
  return <AuthenticatedApp />
}

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  )
}
