export const FINDING_TYPE_LABELS: Record<string, string> = {
  any_to_any_allow: 'Any-to-Any Allow',
  overly_permissive: 'Overly Permissive',
  duplicate_rule: 'Duplicate Rule',
  shadowed_rule: 'Shadowed Rule',
  same_action_shadowed_rule: 'Redundant Rule',
  conflicting_shadowed_rule: 'Conflicting Shadowed Rule',
  partial_shadowed_rule: 'Partially Shadowed Rule',
  shadowing_not_evaluated: 'Shadowing Not Evaluated',
  disabled_rule: 'Disabled Rule',
  zero_hit_rule: 'Zero Hits',
  low_usage_rule: 'Low Usage',
  risky_service: 'Risky Service',
  no_logging: 'No Logging',
  no_documentation: 'No Documentation',
  temporary_rule: 'Temporary Rule',
  naming_quality: 'Poor Rule Name',
  expired_rule: 'Expired Schedule',
  nat_complexity: 'NAT Rule',
  vpn_access: 'Broad VPN Access',
  negated_object: 'Negated Object',
  rdp_exposed: 'RDP Exposed',
  ssh_exposed: 'SSH Exposed',
  database_exposed: 'Database Exposed',
  cleartext_service: 'Cleartext Protocol',
  inbound_from_internet: 'Inbound From Internet',
  lateral_movement_risk: 'Lateral Movement Risk',
  mergeable_rules: 'Consolidation Candidate',
  no_cleanup_rule: 'Missing Cleanup Rule',
  rule_order_optimization: 'Rule Order Optimization',
  large_rule_section: 'Oversized Section',
  unused_object: 'Unused Object',
  duplicate_object: 'Duplicate Object',
  empty_group: 'Empty Group',
  large_group: 'Large Group',
  broad_network: 'Broad Network',
  service_range: 'Large Port Range',
  import_quality: 'Import Quality',
  analysis_configuration: 'Analysis Configuration',
}

export function findingTypeLabel(type: string): string {
  return FINDING_TYPE_LABELS[type] || type.replace(/_/g, ' ')
}

export function shortFindingTypeLabel(type: string): string {
  const short: Record<string, string> = {
    any_to_any_allow: 'Any/Any',
    overly_permissive: 'Permissive',
    duplicate_rule: 'Dup',
    shadowed_rule: 'Shadow',
    same_action_shadowed_rule: 'Redundant',
    conflicting_shadowed_rule: 'Conflict',
    partial_shadowed_rule: 'Partial Shadow',
    shadowing_not_evaluated: 'Shadow Skipped',
    zero_hit_rule: 'Zero Hit',
    no_logging: 'No Log',
    risky_service: 'Risky Svc',
    temporary_rule: 'Temp',
    analysis_configuration: 'Config',
    import_quality: 'Import',
  }
  return short[type] || findingTypeLabel(type)
}

export const SHADOW_FINDING_TYPES = new Set([
  'shadowed_rule',
  'same_action_shadowed_rule',
  'conflicting_shadowed_rule',
  'partial_shadowed_rule',
])
