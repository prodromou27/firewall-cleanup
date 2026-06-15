import axios from 'axios'

// Authentication is session-cookie based. On login the backend sets an
// HttpOnly cookie (pi_session); the browser sends it automatically on every
// same-origin request. The frontend never sees or stores the token.
//
// All requests go through the same-origin path (`/api`, proxied to the backend
// in dev) so the cookie is included without any CORS credential gymnastics.
// `withCredentials` ensures the cookie rides along even if a request ends up
// being treated as cross-origin.

// Same-origin base for direct fetch() calls (downloads, etc.). Empty string =>
// relative URLs like `/api/...`, which the dev server proxies to the backend.
export const API_BASE = ''

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  withCredentials: true,
})

// On any 401, drop to the login screen. A custom event lets the AuthProvider
// react without this module importing React.
let _redirectingToLogin = false
api.interceptors.response.use(
  r => r,
  err => {
    if (err?.response?.status === 401 && !_redirectingToLogin) {
      _redirectingToLogin = true
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
      // allow subsequent 401s after a tick (e.g. parallel requests)
      setTimeout(() => { _redirectingToLogin = false }, 500)
    }
    return Promise.reject(err)
  },
)

export default api

// ── Auth ─────────────────────────────────────────────────────────────────────
export interface CurrentUser {
  id: string
  email: string
  full_name: string | null
  role: string
  customer_ids: string[] | null // null => all customers (global role)
}

export const login = (email: string, password: string) =>
  api.post('/auth/login', { email, password }).then(r => r.data.user as CurrentUser)

export const logout = () =>
  api.post('/auth/logout').then(r => r.data)

export const logoutAll = () =>
  api.post('/auth/logout-all').then(r => r.data)

export const changePassword = (current_password: string, new_password: string) =>
  api.post('/auth/change-password', { current_password, new_password }).then(r => r.data)

export const getMe = () =>
  api.get('/auth/me').then(r => r.data.user as CurrentUser)

// â”€â”€ Customers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getCustomers = (params?: Record<string, string>) =>
  api.get('/customers', { params }).then(r => r.data)

export const getCustomer = (id: string) =>
  api.get(`/customers/${id}`).then(r => r.data)

export const getCustomerStats = (id: string) =>
  api.get(`/customers/${id}/stats`).then(r => r.data)

export const createCustomer = (data: Record<string, string>) =>
  api.post('/customers', data).then(r => r.data)

export const updateCustomer = (id: string, data: Record<string, string>) =>
  api.patch(`/customers/${id}`, data).then(r => r.data)

export const deleteCustomer = (id: string) =>
  api.delete(`/customers/${id}`).then(r => r.data)

// â”€â”€ Policies â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getPolicies = (params?: Record<string, string>) =>
  api.get('/policies', { params }).then(r =>
    // API returns paginated wrapper; unwrap for backwards compat with list consumers
    Array.isArray(r.data) ? r.data : (r.data.policies ?? r.data)
  )

export const getPolicy = (id: string) =>
  api.get(`/policies/${id}`).then(r => r.data)

export const deletePolicy = (id: string) =>
  api.delete(`/policies/${id}`).then(r => r.data)

export const reanalyzePolicy = (id: string) =>
  api.post(`/policies/${id}/reanalyze`).then(r => r.data)

export const getFindingsTrend = (customerId?: string, days = 90) =>
  api.get('/policies/findings-trend', {
    params: { days, ...(customerId ? { customer_id: customerId } : {}) },
  }).then(r => r.data as { days: number; points: Array<{ date: string; total: number; runs: number; Critical: number; High: number; Medium: number; Low: number; Informational: number }> })

export const getDashboardStats = (customerId?: string) =>
  api.get('/policies/stats', { params: customerId ? { customer_id: customerId } : undefined }).then(r => r.data)

export const getPolicyScorecard = (policyId: string) =>
  api.get(`/policies/${policyId}/scorecard`).then(r => r.data)

export const getPolicyHealth = (policyId: string) =>
  api.get(`/policies/${policyId}/health`).then(r => r.data)

export const getRules = (policyId: string, params?: Record<string, string | number | boolean>) =>
  api.get(`/policies/${policyId}/rules`, { params: params as Record<string, string> }).then(r => r.data)

export const getRule = (policyId: string, ruleId: string) =>
  api.get(`/policies/${policyId}/rules/${ruleId}`).then(r => r.data)

// â”€â”€ Findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getFindings = (params?: Record<string, string | number>) =>
  api.get('/findings', { params: params as Record<string, string> }).then(r => r.data)

export const getFinding = (id: string) =>
  api.get(`/findings/${id}`).then(r => r.data)

export const updateFinding = (id: string, data: Record<string, string | undefined>) =>
  api.patch(`/findings/${id}`, data).then(r => r.data)

export const bulkUpdateFindings = (
  ids: string[],
  data: { status?: string; engineer_comment?: string; priority?: string; assigned_to?: string },
) => {
  const params = new URLSearchParams()
  ids.forEach(id => params.append('finding_ids', id))
  return api.post(`/findings/bulk-update?${params.toString()}`, data).then(r => r.data)
}

// â”€â”€ Objects â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getObjects = (params?: Record<string, string | number>) =>
  api.get('/objects', { params: params as Record<string, string> }).then(r => r.data)

// â”€â”€ Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const uploadPolicy = (formData: FormData) =>
  api.post('/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)

// â”€â”€ Reports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getReportUrl = (
  policyId: string,
  format: 'html' | 'excel' | 'csv' | 'json',
  filters?: {
    severities?: string[]
    finding_types?: string[]
    statuses?: string[]
    finding_ids?: string[]
    include_rules?: boolean
  }
) => {
  const params = new URLSearchParams()
  if (filters?.severities?.length)     params.set('severities',    filters.severities.join(','))
  if (filters?.finding_types?.length)  params.set('finding_types', filters.finding_types.join(','))
  if (filters?.statuses?.length)       params.set('statuses',      filters.statuses.join(','))
  if (filters?.finding_ids?.length)    params.set('finding_ids',   filters.finding_ids.join(','))
  if (filters?.include_rules === false) params.set('include_rules', 'false')
  const qs = params.toString()
  return `/api/reports/${policyId}/${format}${qs ? '?' + qs : ''}`
}

// â”€â”€ Settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getSettings = () =>
  api.get('/settings').then(r => r.data)

// â”€â”€ Devices â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getDevices = (customerId?: string) =>
  api.get('/devices', { params: customerId ? { customer_id: customerId } : undefined }).then(r => r.data)

export const createDevice = (data: Record<string, unknown>) =>
  api.post('/devices', data).then(r => r.data)

export const updateDevice = (id: string, data: Record<string, unknown>) =>
  api.patch(`/devices/${id}`, data).then(r => r.data)

export const deleteDevice = (id: string) =>
  api.delete(`/devices/${id}`).then(r => r.data)

export const testDevice = (id: string) =>
  api.post(`/devices/${id}/test`).then(r => r.data)

export const syncDevice = (id: string) =>
  api.post(`/devices/${id}/sync`).then(r => r.data)

export const getDeviceSyncStatus = (id: string) =>
  api.get(`/devices/${id}/sync-status`).then(r => r.data)

export const getDeviceVulnerabilities = (id: string, refresh = false) =>
  api.get(`/devices/${id}/vulnerabilities${refresh ? '?refresh=true' : ''}`).then(r => r.data)

// ── Compliance ─────────────────────────────────────────────────────────────────
export const getComplianceFrameworks = () =>
  api.get('/compliance/frameworks').then(r => r.data)

export const getCompliance = (policyId: string, framework: string) =>
  api.get(`/compliance/${policyId}`, { params: { framework } }).then(r => r.data)

export const getComplianceAll = (policyId: string) =>
  api.get(`/compliance/${policyId}/all`).then(r => r.data)

// ── Settings (extended) ────────────────────────────────────────────────────────
export const updateSettings = (data: Record<string, unknown>) =>
  api.patch('/settings', data).then(r => r.data)

export const resetDeviceSync = (id: string) =>
  api.post(`/devices/${id}/reset-sync`).then(r => r.data)

export const getDeviceTrends = (id: string) =>
  api.get(`/devices/${id}/trends`).then(r => r.data)

// â”€â”€ Policies: get by customer scoped â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getPoliciesForCustomer = (customerId: string) =>
  api.get('/policies', { params: { customer_id: customerId } }).then(r =>
    Array.isArray(r.data) ? r.data : (r.data.policies ?? [])
  )

// â”€â”€ Revisions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getRevisions = (params?: { policy_id?: string; device_id?: string; limit?: number }) =>
  api.get('/revisions', { params: params as Record<string, string> }).then(r => r.data)

export const getRevision = (id: string) =>
  api.get(`/revisions/${id}`).then(r => r.data)

// â”€â”€ Policy advanced â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getPolicyRiskScore = (policyId: string) =>
  api.get(`/policies/${policyId}/risk-score`).then(r => r.data)

export const getPermissiveAnalysis = (policyId: string) =>
  api.get(`/policies/${policyId}/permissive-analysis`).then(r => r.data)

export const getRulesExportUrl = (
  policyId: string,
  params: Record<string, string | number | boolean> = {}
) => {
  const qs = new URLSearchParams(
    Object.entries({ ...params, export: 'true' }).map(([k, v]) => [k, String(v)])
  ).toString()
  return `/api/policies/${policyId}/rules?${qs}`
}

// â”€â”€ Findings advanced â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export const getFindingsExportUrl = (params: Record<string, string> = {}) => {
  const qs = new URLSearchParams({ ...params, export: 'true' }).toString()
  return `/api/findings?${qs}`
}

export const addFindingComment = (id: string, comment: string, author = 'engineer') =>
  api.post(`/findings/${id}/comments`, { comment, author }).then(r => r.data)

export const getFindingComments = (id: string) =>
  api.get(`/findings/${id}/comments`).then(r => r.data)

// ── Recommendation Library ─────────────────────────────────────────────────────
export const getRecommendations = () =>
  api.get('/recommendations').then(r => r.data as { recommendations: Array<{ finding_type: string; recommendation: string }> })

export const getRecommendation = (findingType: string) =>
  api.get(`/recommendations/${findingType}`).then(r => r.data as { finding_type: string; recommendation: string })
