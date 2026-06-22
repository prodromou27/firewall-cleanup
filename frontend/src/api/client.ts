import api, { API_BASE } from './http'

import type {
  Customer as AppCustomer,
  Finding as AppFinding,
  FirewallDeviceT as AppFirewallDevice,
  FirewallObject as AppFirewallObject,
  Policy as AppPolicy,
} from '../types'

export { API_BASE }
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

export interface AuditEvent {
  id: string
  ts: string | null
  event: string
  user_id: string | null
  actor_email: string | null
  customer_id: string | null
  source_ip: string | null
  target_type: string | null
  target_id: string | null
  detail: Record<string, unknown>
}

export const getAuditEvents = (params?: Record<string, string | number>) =>
  api.get('/audit', { params: params as Record<string, string> })
    .then(r => r.data as { total: number; page: number; page_size: number; events: AuditEvent[] })

// Customers
export type Customer = AppCustomer

export const getCustomers = (params?: Record<string, string | number>) =>
  api.get('/customers', { params: params as Record<string, string> }).then(r => r.data as Customer[])

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

// Policies
export type PolicySummary = AppPolicy

export interface PaginatedPolicies {
  total: number
  page: number
  page_size: number
  policies: PolicySummary[]
}

export const getPolicies = (params?: Record<string, string | number>) =>
  api.get('/policies', { params }).then(r =>
    // API returns paginated wrapper; unwrap for backwards compat with list consumers
    (Array.isArray(r.data) ? r.data : (r.data.policies ?? r.data)) as PolicySummary[]
  )

export const getPoliciesPage = (params?: Record<string, string | number>) =>
  api.get('/policies', { params }).then(r => r.data as PaginatedPolicies)

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

export interface CleanupWave {
  id: number
  name: string
  description: string
  rollback: string
  finding_count: number
  candidate_rule_count: number
  candidate_object_count: number
  risk_weight: number
  risk_weight_pct: number
  risk_reduction_pct: number
  severity_breakdown: Record<string, number>
}
export interface CleanupPlan {
  customer_id: string | null
  total_findings: number
  total_risk_weight: number
  risk_metric_label: string
  waves: CleanupWave[]
  unscheduled_count: number
  generated_for: string
}
export interface PolicyChange {
  policy_id: string
  firewall_name: string
  vendor: string | null
  last_synced: string | null
  revision_number: number | null
  rules_added: number
  rules_removed: number
  rules_modified: number
  rule_changes_total: number
  change_summary: string | null
  severity_delta: Record<string, number>
  finding_type_delta: Record<string, number>
  finding_type_labels: Record<string, string>
  new_high_risk: boolean
  sample_changes: Array<Record<string, unknown>>
}
export const getChanges = (customerId?: string) =>
  api.get('/changes', { params: customerId ? { customer_id: customerId } : undefined })
    .then(r => r.data as { customer_id: string | null; policies: PolicyChange[] })

export const getCleanupPlan = (customerId?: string) =>
  api.get('/cleanup-plan', { params: customerId ? { customer_id: customerId } : undefined })
    .then(r => r.data as CleanupPlan)

export const getCleanupTicketsUrl = (customerId?: string, wave?: number) => {
  const p = new URLSearchParams()
  if (customerId) p.set('customer_id', customerId)
  if (wave) p.set('wave', String(wave))
  const q = p.toString()
  return `/api/cleanup-plan/tickets.csv${q ? `?${q}` : ''}`
}

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

// Findings
export interface FindingListResponse {
  total: number
  page: number
  page_size: number
  severity_counts: Record<string, number>
  findings: AppFinding[]
}

export const getFindings = (params?: Record<string, string | number>) =>
  api.get('/findings', { params: params as Record<string, string> }).then(r => r.data as FindingListResponse)

export const getFinding = (id: string) =>
  api.get(`/findings/${id}`).then(r => r.data)

export interface Remediation {
  vendor: string
  finding_type: string
  category: string | null
  category_label: string
  guidance: string
  vendor_specific: boolean
  read_only_note: string
}
export const getRemediation = (findingType: string, vendor?: string) =>
  api.get('/remediation', { params: { finding_type: findingType, ...(vendor ? { vendor } : {}) } })
    .then(r => r.data as Remediation)

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

// Objects
export interface ObjectListResponse {
  total: number
  page: number
  page_size: number
  objects: AppFirewallObject[]
}
export const getObjects = (params?: Record<string, string | number>) =>
  api.get('/objects', { params: params as Record<string, string> }).then(r => r.data as ObjectListResponse)

// Upload
type UploadProgressEvent = { loaded: number; total?: number }

export const uploadPolicy = (formData: FormData, onUploadProgress?: (event: UploadProgressEvent) => void) =>
  api.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress,
  }).then(r => r.data)

// Reports
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

// Settings
export const getSettings = () =>
  api.get('/settings').then(r => r.data)

// Devices
export const getDevices = (customerId?: string) =>
  api.get('/devices', { params: customerId ? { customer_id: customerId } : undefined }).then(r =>
    Array.isArray(r.data) ? r.data : (r.data.devices ?? [])
  )

export interface PaginatedDevices {
  total: number
  page: number
  page_size: number
  devices: AppFirewallDevice[]
}

export const getDevicesPage = (params?: Record<string, string | number>) =>
  api.get('/devices', { params }).then(r => r.data as PaginatedDevices)

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

// Policies: get by customer scoped
export const getPoliciesForCustomer = (customerId: string) =>
  api.get('/policies', { params: { customer_id: customerId } }).then(r =>
    Array.isArray(r.data) ? r.data : (r.data.policies ?? [])
  )

// Revisions
export const getRevisions = (params?: { policy_id?: string; device_id?: string; limit?: number }) =>
  api.get('/revisions', { params: params as Record<string, string> }).then(r => r.data)

export const getRevision = (id: string) =>
  api.get(`/revisions/${id}`).then(r => r.data)

// Policy advanced
export const getPolicyRiskScore = (policyId: string) =>
  api.get(`/policies/${policyId}/risk-score`).then(r => r.data)

export const getPermissiveAnalysis = (policyId: string) =>
  api.get(`/policies/${policyId}/permissive-analysis`).then(r => r.data)

export interface PublicExposure {
  policy_id: string
  firewall_name: string
  vendor: string
  nat_available: boolean
  nat_rule_count: number
  public_ips: string[]
  exposed_ports: number[]
  exposures: Array<{
    public_ip: string
    internal_target: string
    ports: number[]
    service_any: boolean
    source: 'nat' | 'policy'
    nat_rules: (string | number)[]
    security_rules: (string | number)[]
  }>
  risk_score: number
  interfaces_available: boolean
  public_interfaces: Array<{ name: string; ip: string | null; zone: string | null; wan_facing: boolean; mgmt_access: boolean; has_public_ip: boolean }>
  public_ip_inventory: Array<{ public_ip: string; source_type: string; reference: string; mapped_internal: string | null; exposed_service: string | null; confidence: string; notes: string }>
  findings: Array<{ id: string; finding_type: string; severity: string; title: string; status: string }>
}

export const getPublicExposure = (policyId: string) =>
  api.get(`/policies/${policyId}/public-exposure`).then(r => r.data as PublicExposure)

export const getRulesExportUrl = (
  policyId: string,
  params: Record<string, string | number | boolean> = {}
) => {
  const qs = new URLSearchParams(
    Object.entries({ ...params, export: 'true' }).map(([k, v]) => [k, String(v)])
  ).toString()
  return `/api/policies/${policyId}/rules?${qs}`
}

// Findings advanced
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

// ── Reporting ────────────────────────────────────────────────────────────────
export interface ReportSectionDef { key: string; name: string; type: string; group: string; default: boolean }
export interface TemplateSection {
  id?: string; section_key: string; section_name?: string; section_type?: string
  enabled: boolean; display_order: number; custom_text?: string | null; config?: Record<string, unknown>
}
export interface ReportTemplate {
  id: string; name: string; description?: string | null; template_type: string; audience: string
  is_customer_facing: boolean; default_export_format: string; default_detail_level: string
  branding_config: Record<string, unknown>; cover_page_config: Record<string, unknown>
  introduction_text?: string | null; methodology_text?: string | null; disclaimer_text?: string | null
  footer_text?: string | null; default_finding_categories: string[]; customer_id?: string | null
  is_default: boolean; sections: TemplateSection[]
}
export interface GeneratedReportRow {
  id: string; report_type: string; export_format: string; customer_id: string | null
  firewall_name: string | null; file_name: string; generated_by: string | null; generated_at: string | null
  selected_sections: string[]; template_id: string | null; policy_id: string | null; analysis_run_id: string | null
}
export interface GeneratedReportsPage {
  total: number
  page: number
  page_size: number
  reports: GeneratedReportRow[]
}
export interface ReportAnalysisRun {
  id: string
  status: string
  started_at: string | null
  completed_at: string | null
  findings_created: number
  run_by: string | null
}

export const getReportSections = () =>
  api.get('/report-sections/catalog').then(r => r.data as { sections: ReportSectionDef[]; default_sections: string[] })
export const getReportPlaceholders = () =>
  api.get('/report-placeholders').then(r => r.data as { placeholders: string[] })
export const getReportFindingCategories = () =>
  api.get('/report-finding-categories').then(r => r.data as { categories: Array<{ key: string; label: string }> })

export const listReportTemplates = () =>
  api.get('/report-templates').then(r => r.data as { templates: ReportTemplate[] })
export const getReportTemplate = (id: string) =>
  api.get(`/report-templates/${id}`).then(r => r.data as ReportTemplate)
export const createReportTemplate = (body: Partial<ReportTemplate> & { sections?: TemplateSection[] }) =>
  api.post('/report-templates', body).then(r => r.data as ReportTemplate)
export const updateReportTemplate = (id: string, body: Partial<ReportTemplate> & { sections?: TemplateSection[] }) =>
  api.put(`/report-templates/${id}`, body).then(r => r.data as ReportTemplate)
export const deleteReportTemplate = (id: string) =>
  api.delete(`/report-templates/${id}`).then(r => r.data)
export const cloneReportTemplate = (id: string) =>
  api.post(`/report-templates/${id}/clone`).then(r => r.data as ReportTemplate)
export const setDefaultReportTemplate = (id: string) =>
  api.post(`/report-templates/${id}/default`).then(r => r.data)
export const listReportAnalysisRuns = (policyId: string) =>
  api.get(`/reports/policies/${policyId}/analysis-runs`)
    .then(r => r.data as { analysis_runs: ReportAnalysisRun[] })

export const uploadReportLogo = (file: File) => {
  const fd = new FormData(); fd.append('file', file)
  return api.post('/report-templates/logo', fd).then(r => r.data as { logo_ref: string; data_uri: string })
}

export interface GenerateBody {
  policy_id: string; template_id?: string; export_format: string; report_type?: string
  analysis_run_id?: string
  sections?: string[]; finding_categories?: string[]; filters?: Record<string, unknown>
  branding?: Record<string, unknown>; texts?: Record<string, string>; custom_sections?: Record<string, string>
}
export const generateReport = (body: GenerateBody) =>
  api.post('/reports/generate', body).then(r => r.data as { id: string; file_name: string; export_format: string; download_url: string })
export const previewReportUrl = '/api/reports/preview'   // POST → HTML (use fetch for srcdoc)
export const listGeneratedReports = (customerId?: string) =>
  api.get('/reports', { params: customerId ? { customer_id: customerId } : undefined })
    .then(r => r.data as GeneratedReportsPage)
export const listGeneratedReportsPage = (params?: Record<string, string | number>) =>
  api.get('/reports', { params }).then(r => r.data as GeneratedReportsPage)
export const reportDownloadUrl = (id: string) => `/api/reports/${id}/download`
