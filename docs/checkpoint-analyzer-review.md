# Check Point analyzer review

## Corrections

- File imports read the management API `objects-dictionary`, resolve UID references and preserve UID-only group members. Missing match fields remain missing rather than becoming Any. Nested display sections are walked without treating section headers as rules. A zero-length IPv4 mask remains `/0`.
- Shared action normalization preserves unknown and inline-layer actions instead of treating them as Accept. Negation flags are parsed consistently, including string booleans. Negated match fields remain unknown to set-based analysis rather than being interpreted as positive sets.
- Exclusion groups retain their include/except references and their distinct type. Address expansion does not interpret them as empty service groups or ordinary unions. Exact subtraction is not implemented.
- Check Point service ports are expanded as separate terms, including comma-separated unions, bounds and source ports. Malformed definitions and additional unmodeled matching conditions become unknown. Scalar object fields describe the first term; analyzer expansion uses retained raw data, avoiding fabricated all-port or contiguous-range findings.
- Actual layer identity is kept separately from display sections and used with install-on scope for duplicate/shadow comparisons. Live synchronization persists rule UID, install-on, users, VPN and raw enforcement metadata. Stable Check Point rule UIDs avoid collisions where multiple layers use the same rule number.
- Inline parent rules are retained. Retrieved or embedded child rules whose parent constraints are not modeled are tagged unresolved; address/service expansion and consolidation checks suppress unsupported claims about their effective traffic. This is a conservative gate, not full inline-layer evaluation. See Check Point's [Ordered Layers and Inline Layers](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/Ordered-Layers-and-Inline-Layers.htm).
- Live collection accumulates objects from every rulebase page. Built-in definitions remain available for expansion while cleanup excludes system-domain objects. Object merging no longer compares every inline object dictionary against the full object list.
- Absent Check Point tracking metadata is treated as unknown in engine rule normalization, not evidence that logging was explicitly disabled.

## Validation and rollout

Regression coverage includes file parsing, exact service expansion, non-terminal actions, exclusion groups, cross-layer context, multi-page dictionary collection and live translation through database persistence. The full backend suite passed 461 tests. Validation used synthetic local fixtures, not a live management server.

No new schema migration is introduced by this increment. Reanalysis can use raw fields retained in existing records. Records written by older live synchronization code may lack layer, install-on, VPN/user or original service definitions; those need resync or reimport before the corrections can use the missing information. Existing stored findings are not automatically rewritten. The earlier review-history migration still applies when upgrading from a version before that feature.

Remaining work includes complete inline-parent intersections, ordered-layer end-to-end evaluation, exclusion-set subtraction, other advanced Check Point service/application constraints and validation against representative sanitized customer exports. These changes do not establish a measured production false-positive rate or authorize firewall changes.
