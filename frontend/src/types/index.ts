export interface Customer {
  id: string
  name: string
  description: string | null
  contact_name: string | null
  contact_email: string | null
  industry: string | null
  status: 'active' | 'archived'
  tags: string | null
  notes: string | null
  total_policies: number
  total_rules: number
  total_findings: number
  high_findings: number
  created_at: string | null
  updated_at: string | null
}

export interface CustomerStats extends Customer {
  customer: Customer
  medium_findings: number
  low_findings: number
  info_findings: number
  enabled_rules: number
  disabled_rules: number
  findings_by_severity: Array<{ severity: string; count: number }>
  findings_by_type: Array<{ type: string; count: number }>
  findings_by_status: Array<{ status: string; count: number }>
  vendor_distribution: Array<{ vendor: string; count: number }>
  policies: PolicyRow[]
}

export interface PolicyRow {
  id: string
  firewall_name: string
  vendor: string
  policy_package: string
  upload_date: string | null
  rule_count: number
  finding_count: number
  high_finding_count: number
  analysis_status: string
}

export interface Policy {
  id: string
  customer_id: string
  customer_name: string
  firewall_name: string
  vendor: string
  policy_package: string
  upload_date: string | null
  original_filename: string | null
  rule_count: number
  object_count: number
  finding_count: number
  high_finding_count: number
  analysis_status: 'pending' | 'running' | 'completed' | 'failed' | 'parsing'
  analysis_error: string | null
  notes?: string
  findings_by_type?: Array<{ type: string; count: number }>
  findings_by_severity?: Array<{ severity: string; count: number }>
  complexity_score?: number | null
  complexity_breakdown?: Record<string, { value: number; label: string; points: number }> | null
  cleanup_readiness_score?: number | null
  health_score?: number | null
  top_risk_drivers?: Array<{ type: string; count: number }>
}

export interface Rule {
  id: string
  rule_id: string
  rule_uid: string
  rule_number: number
  rule_name: string
  section: string
  source_interfaces: string[]
  destination_interfaces: string[]
  sources: string[]
  destinations: string[]
  services: string[]
  applications: string[]
  action: string
  schedule: string
  enabled: boolean
  logging_enabled: boolean
  nat_enabled: boolean
  comments: string
  hit_count: number | null
  last_hit: string | null
  first_hit: string | null
  risk_score: number
  finding_count: number
  risk_factors?: Record<string, { points: number; reason: string }>
  findings?: Finding[]
  raw_data?: Record<string, unknown>
}

export interface FirewallObject {
  id: string
  policy_id: string
  object_name: string
  object_type: string
  value: string | null
  protocol: string | null
  port_start: number | null
  port_end: number | null
  members: string[]
  member_count?: number
  comment: string
  is_unused: boolean
  is_duplicate?: boolean
  is_empty_group?: boolean
  is_large_group?: boolean
}

export type FindingSeverity = 'High' | 'Medium' | 'Low' | 'Informational'
export type FindingConfidence = 'High' | 'Medium' | 'Low'
export type FindingStatus =
  | 'New'
  | 'Review Required'
  | 'In Review'
  | 'Requires Business Validation'
  | 'Requires Customer Confirmation'
  | 'Confirmed Cleanup Candidate'
  | 'Manual Change Required'
  | 'Change Planned Outside Tool'
  | 'Cleanup Completed Outside Tool'
  | 'False Positive'
  | 'Accepted Risk'
  | 'Deferred'
  | 'Reopened'

export type FindingPriority = 'Immediate' | 'High' | 'Standard' | 'Low' | 'Monitor'

export interface AffectedRuleData {
  id: string
  rule_id: string | null
  rule_number: number | null
  rule_name: string
  section: string | null
  sources: string[]
  destinations: string[]
  services: string[]
  applications: string[]
  action: string | null
  enabled: boolean
  logging_enabled: boolean
  hit_count: number | null
  last_hit: string | null
  first_hit: string | null
  comments: string | null
  source_any: boolean
  destination_any: boolean
  service_any: boolean
}

export interface Finding {
  id: string
  policy_id: string
  vendor: string | null
  finding_type: string
  severity: FindingSeverity
  confidence: FindingConfidence
  priority: FindingPriority
  title: string
  description: string
  affected_rules: string[]
  affected_rules_data?: AffectedRuleData[]
  affected_objects: string[]
  recommendation: string
  status: FindingStatus
  engineer_comment: string | null
  assigned_to: string | null
  due_date: string | null
  risk_score: number
  created_at: string | null
  updated_at: string | null
  evidence?: Record<string, unknown>
  comments?: FindingComment[]
  risk_acceptance?: {
    reason: string | null
    expiry: string | null
    ref: string | null
    accepted_by: string | null
  } | null
}

export interface FindingComment {
  id: string
  author: string
  comment: string
  old_status: string | null
  new_status: string | null
  created_at: string | null
}

export interface RiskHeatmapEntry {
  policy_id: string
  firewall_name: string
  customer_id: string
  customer_name: string
  vendor: string
  risk_score: number
  finding_count: number
  high_finding_count: number
  rule_count: number
}

export interface DashboardStats {
  total_customers: number
  total_policies: number
  total_rules: number
  enabled_rules: number
  disabled_rules: number
  total_findings: number
  high_findings: number
  findings_by_type: Array<{ type: string; count: number }>
  findings_by_severity: Array<{ severity: string; count: number }>
  vendor_distribution: Array<{ vendor: string; count: number }>
  top_customers_by_risk: Array<{
    id: string; name: string; high_findings: number
    total_findings: number; total_policies: number; total_rules: number
  }>
  risk_heatmap: RiskHeatmapEntry[]
}

export interface FirewallDeviceT {
  id: string
  customer_id: string
  name: string
  vendor: 'FortiGate' | 'CheckPoint' | 'PaloAlto' | 'CiscoASA' | string
  host: string
  port: number | null
  use_ssl: boolean
  verify_ssl: boolean
  vdom: string | null
  cp_domain: string | null
  cp_policy_package: string | null
  cp_management_type: 'SmartCenter' | 'MDS' | 'Smart-1Cloud' | string
  has_token: boolean
  has_credentials: boolean
  /** Masked username hint returned by the API (e.g. "ad***"). Never the full plaintext value. */
  username_hint?: string
  sync_interval_hours: number | null
  sync_status: 'never' | 'running' | 'ok' | 'error'
  last_sync_at: string | null
  last_error: string | null
  last_policy_id: string | null
  // Inventory fields
  fw_model: string | null
  os_version: string | null
  management_platform: string | null
  environment_type: string
  location: string | null
  fw_role: string
  criticality: string
  // Network / HA (populated on live sync)
  serial_number: string | null
  ha_mode: string | null
  ha_peer: string | null
  device_interfaces: string | null  // JSON: {name,ip,mask,type,status}[]
  created_at: string | null
}

export interface DeviceTrendSuggestion {
  type: string
  severity: 'High' | 'Medium' | 'Low' | 'Informational'
  rule_id?: string
  rule_name?: string
  message: string
  syncs_zero_hit?: number
  modification_count?: number
  finding_count?: number
  note?: string
}

export interface DeviceTrends {
  device_id: string
  policy_id: string | null
  revision_count: number
  sync_interval_hours: number | null
  suggestions: DeviceTrendSuggestion[]
  change_activity: Array<{
    rule_id: string
    rule_name: string
    modification_count: number
    last_changed_at: string | null
  }>
  revision_timeline: Array<{
    id: string
    revision_number: number
    synced_at: string | null
    rule_count: number | null
    finding_count: number | null
    high_finding_count: number | null
    rules_added: number | null
    rules_removed: number | null
    rules_modified: number | null
    change_summary: string | null
  }>
  finding_trend: Array<{
    synced_at: string | null
    finding_count: number
    high_finding_count: number
    revision_number: number
  }>
}

export interface ScorecardDimension {
  key: string
  label: string
  score: number
  weight: number
  detail: string
}

export interface ScorecardImprovement {
  metric: string
  label: string
  count: number
  severity: 'High' | 'Medium' | 'Low'
}

export interface PolicyScorecard {
  policy_id: string
  firewall_name: string
  vendor: string
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  dimensions: ScorecardDimension[]
  strengths: string[]
  improvements: ScorecardImprovement[]
  meta: {
    total_rules: number
    enabled_rules: number
    allow_rules: number
    total_objects: number
  }
}

export interface PolicyRevision {
  id: string
  policy_id: string | null
  device_id: string | null
  revision_number: number
  synced_at: string | null
  sync_source: string | null
  rule_count: number | null
  object_count: number | null
  finding_count: number | null
  high_finding_count: number | null
  rules_added: number | null
  rules_removed: number | null
  rules_modified: number | null
  change_summary: string | null
  policy_hash: string | null
  notes: string | null
  change_detail?: Array<{
    rule_id: string
    change_type: 'added' | 'removed' | 'modified'
    before?: Record<string, unknown>
    after?: Record<string, unknown>
  }>
}
