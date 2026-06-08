import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Upload } from './pages/Upload'
import { Policies, PolicyDetail } from './pages/Policies'
import { Findings } from './pages/Findings'
import { Rulebase } from './pages/Rulebase'
import { Objects } from './pages/Objects'
import { Reports } from './pages/Reports'
import { Scorecard } from './pages/Scorecard'
import { HealthAssessment } from './pages/HealthAssessment'
import { Settings } from './pages/Settings'
import { Customers } from './pages/Customers'
import { CustomerDetail } from './pages/CustomerDetail'
import { Devices } from './pages/Devices'
import { DeviceHistory } from './pages/DeviceHistory'
import { PolicyComparison } from './pages/PolicyComparison'
import { Compliance } from './pages/Compliance'

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Layout>
        <Routes>
          {/* Global routes */}
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/settings" element={<Settings />} />

          {/* Global policy/findings/objects/reports (cross-customer) */}
          <Route path="/policies" element={<Policies />} />
          <Route path="/policies/:id" element={<PolicyDetail />} />
          <Route path="/policies/:policyId/rules" element={<Rulebase />} />
          <Route path="/policies/:policyId/compare" element={<PolicyComparison />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/objects" element={<Objects />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/scorecard" element={<Scorecard />} />
          <Route path="/health" element={<HealthAssessment />} />

          {/* Customer management */}
          <Route path="/customers" element={<Customers />} />

          {/* Customer-scoped routes */}
          <Route path="/customers/:customerId" element={<CustomerDetail />} />
          <Route path="/customers/:customerId/devices" element={<Devices />} />
          <Route path="/customers/:customerId/devices/:deviceId/history" element={<DeviceHistory />} />
          <Route path="/customers/:customerId/policies" element={<Policies />} />
          <Route path="/customers/:customerId/policies/:id" element={<PolicyDetail />} />
          <Route path="/customers/:customerId/findings" element={<Findings />} />
          <Route path="/customers/:customerId/objects" element={<Objects />} />
          <Route path="/customers/:customerId/reports" element={<Reports />} />
          <Route path="/customers/:customerId/compliance" element={<Compliance />} />
          <Route path="/customers/:customerId/scorecard" element={<Scorecard />} />
          <Route path="/customers/:customerId/health" element={<HealthAssessment />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
