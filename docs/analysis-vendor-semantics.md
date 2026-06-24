# PolicyInsight — Vendor Analysis Semantics

Summary of the firewall behaviors PolicyInsight's engine must respect, per
vendor. Read-only: nothing here drives configuration changes. Where a behavior
cannot be verified from official vendor documentation **or** existing parser/
connector data, it is marked **[LIMITATION]** and must not produce high-confidence
findings.

Status legend: ✅ captured today · ⚠️ partial · ❌ not captured (limitation).

## Cross-vendor evaluation model

A finding that depends on rule ordering, shadowing, or duplication is only valid
**within a single evaluation context**. Comparing rules across unrelated contexts
is a false positive. The "context key" per vendor:

| Vendor | Evaluation context key | Captured |
|---|---|---|
| FortiGate | (src interface/zone, dst interface/zone) policy set | ✅ `source_interfaces`/`destination_interfaces` |
| Check Point | policy package → ordered layer → (inline layer) → install-on target | ✅ `_layer`/`section`, `install_on` |
| Palo Alto | rulebase scope (Pre / Local / Post) → (src zone, dst zone) | ✅ `section` (pre/post), zones in interfaces |
| Cisco ASA | ACL bound to (interface, direction) via access-group | ✅ access-group→interface/direction parsed |
| Huawei USG | (source-zone, destination-zone) policy sequence | ✅ `source_zones`/`destination_zones` |

> The engine today flattens all rules into one ordered list for shadow/duplicate
> analysis. **This must become context-scoped** — only compare rules sharing the
> same context key above.

## FortiGate

- **Matching fields**: incoming interface, outgoing interface, source addr,
  destination addr, user/identity, service, schedule, action, status. ✅ (identity ⚠️)
- **Order**: first-match within an interface-pair policy set.
- **Central NAT / VIP**: with Central NAT, the firewall policy destination is the
  **pre-NAT (public) address/VIP**, and DNAT is resolved by a separate Central
  DNAT/VIP table. **Do not assume the VIP object must be the policy destination.**
  ✅ `config firewall vip` is parsed as a destination-NAT object: its normalized
  `value` is the **external IP** (extip — the original/pre-NAT destination the
  policy matches), and `mappedip`/`extport`/`mappedport` are kept in `raw_data`.
  A policy whose destination is a VIP therefore resolves to a concrete address
  (no "unknown" destination), and public-exposure analysis reports the **mapped
  internal host** while keeping the **policy's own service** as the restriction
  (a VIP never invents an "any service" exposure). Inline (per-policy) VIPs only;
  the separate **Central SNAT** table is still ❌ [LIMITATION].
- **Application Control**: an AV/IPS/App-Control **profile** attached to a policy,
  **not** a service constraint. Presence of an app-control profile must not by
  itself downgrade "Any service". ❌ profile data not parsed [LIMITATION].
- **Management-plane exposure**: derived from interface `allowaccess` (admin
  access) and **local-in policies**, not normal firewall policies.
  ❌ local-in + allowaccess not parsed [LIMITATION] — do not infer mgmt exposure
  from ordinary policies.

## Check Point

- **Hierarchy**: policy package → **ordered layers** → optional **inline layers**
  (sub-policies) → rules. ✅ layer tagged on each rule.
- **Match**: source, destination, **Services & Applications** column (services +
  applications + URL categories), VPN column, access roles/users, Install On.
  Applications ✅ (`applications` from `content`); URL categories/access roles ⚠️
  (arrive as application/role names, not typed).
- **Cleanup rule**: per-layer implicit/explicit drop-any-any at the end of a layer.
- **App Control / URL Filtering**: separate ordered layer(s). App-control findings
  must be **layer-aware** (only within an App-Control/URL layer). ✅ layer known.
- **Install On**: rules may apply to specific gateways. **Do not compare rules with
  disjoint install-on targets** for shadowing. ✅ `install_on` captured.
- **NAT**: separate NAT rulebase; original vs translated columns. ⚠️ (normalized
  `nat_rules`; auto-NAT vs manual distinction partial).

## Palo Alto Networks

- **Hierarchy / order**: Panorama **Pre-Rules → device-group/Local rules → Post-Rules
  → default**; first-match within scope. ✅ pre/post captured in `section`
  (Local ⚠️).
- **Match fields**: src zone, dst zone, src addr, dst addr, **Application (App-ID)**,
  service, **URL category**, **User-ID**. Zones ✅, App-ID ✅, URL category ⚠️,
  User-ID ⚠️.
- **`application-default`**: service is whatever App-ID expects — treat as opaque,
  do not equate to "Any service".
- **NAT**: security policy matches **pre-NAT addresses and post-NAT (egress) zone**.
  **Do not match a NAT rule's *translated* destination to the security policy
  destination** — the security rule uses the **original (pre-NAT) destination** with
  the **destination zone of the post-NAT interface**. NAT rule fields ⚠️ [LIMITATION
  for full pre/post-zone correlation].

## Cisco ASA

- **Model**: ACLs applied to an (interface, direction) by `access-group`. ✅ binding
  parsed. An ACL is **not** a global rulebase — it only governs its bound interface.
- **NAT**: object NAT (auto) and twice/manual NAT; **manual NAT (section 1) is
  evaluated before auto NAT (section 2)**; order matters for DNAT. ⚠️ NAT parsing
  partial [LIMITATION for full twice-NAT order].
- **Security levels**: higher→lower implicitly permitted unless ACL denies. ⚠️.
- **Inactive ACEs**: `inactive` keyword = disabled. ⚠️.
- Shadowing/duplicates must be scoped to the **same ACL / interface binding**.

## Huawei USG

- **Match**: source-zone, destination-zone, src addr, dst addr, service,
  application, user/security-group, action; sequence = first-match. ✅ zones,
  ⚠️ application/identity.
- **Destination NAT**: security policy matches the **original (pre-NAT) packet** —
  original destination address/port, not the translated server address.
  **Do not classify destination-NAT exposure from translated/post-NAT values.**
  NAT ⚠️ [LIMITATION].
- Shadowing/duplicates scoped to the **same (src-zone, dst-zone)**.

## NAT → security-policy mapping limitations

Correlating a NAT/VIP/published-service to the security rule that permits it is
**vendor-specific and frequently lossy**:
- FortiGate Central NAT decouples VIP from the policy destination.
- Palo Alto security policy uses pre-NAT address + post-NAT zone.
- Huawei matches original packet.
- Cisco depends on NAT section order + ACL interface.
When correlation cannot be made with confidence, **lower confidence to Medium/Low**
and never assert a Critical exposure on NAT alone.

## Public exposure confidence model

| Evidence present | Confidence |
|---|---|
| Public interface IP **and** matching security rule **and** NAT/VIP | High |
| Security rule (public→internal) only, no NAT/interface corroboration | Medium |
| NAT/VIP only, no matching security rule | Low |
| NAT data missing | Informational (import-quality note only) |

## Detector prerequisite matrix

| Detector | Needs | If missing |
|---|---|---|
| any_to_any_allow / overly_permissive | enabled+allow rule, full expansion | skip rule |
| duplicate_rule | full expansion (no `unknown`), **same context key** | skip pair |
| shadowed_rule (same/conflict/partial) | full expansion, rule order, **same context key**, schedule compat | `shadowing_not_evaluated` (Informational) |
| risky/exposed/cleartext service | expanded services + source classification | reduce confidence |
| zero_hit_rule | `hit_count==0` **and** hit-count source available | Informational import-quality note |
| low_usage_rule | `last_hit` present | skip |
| unused_object | full group expansion (direct+indirect) | skip / reduce |
| empty_group | customer (non-builtin) group, expansion complete | suppress builtins |
| nat / public_exposure | NAT data + interface/policy evidence (vendor-aware) | Informational note / lower confidence |
| version EOL/outdated | parsed version **and** Version Catalog match | Informational only |
| mgmt-plane exposure (FortiGate) | local-in/allowaccess data | do not infer from firewall policy [LIMITATION] |

## Known data gaps (limitations) to close with vendor docs/parsers

1. FortiGate: Central NAT table, VIP↔policy mapping, local-in policies, interface `allowaccess`, app-control profiles.
2. Palo Alto: Local (device-group) scope vs pre/post, URL category + User-ID typing, NAT pre/post-zone correlation.
3. Cisco ASA: twice-NAT ordering, ACE `inactive`, security-level inference.
4. Huawei: destination-NAT original-packet fields, application/identity typing.
5. Check Point: URL-category/access-role typing, auto vs manual NAT.
