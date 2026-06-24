# PolicyInsight — Analysis Scope (per vendor)

PolicyInsight is strictly **read-only**. It ingests firewall configuration,
normalizes it into a vendor-agnostic model, and runs a battery of detectors.
Nothing is ever written back to a device.

## 1. Core principle: vendor-agnostic analysis

The single most important design fact:

> **All analysis runs on a normalized model. Vendors differ only in how data is
> ingested and normalized — not in how it is analyzed.**

```
                 INGESTION (per-vendor)            ANALYSIS (vendor-agnostic)
 ┌───────────┐   ┌───────────────────────┐   ┌──────────────────────────────┐
 │ File      │──▶│ parsers/<vendor>.py    │   │ normalizer.py (expand/resolve│
 │ upload    │   │ → (rules, objects)     │──▶│   groups, services, IPs)     │──▶ findings
 └───────────┘   └───────────────────────┘   │ engine.run_analysis()        │
 ┌───────────┐   ┌───────────────────────┐   │ + nat_exposure / interfaces  │
 │ Live sync │──▶│ connectors/<vendor>.py │   │ + version_intel / cve_checker│
 │ (device)  │   │ → live_sync._translate │──▶│                              │
 └───────────┘   └───────────────────────┘   └──────────────────────────────┘
```

Two ingestion paths produce the **same** normalized structures:

- **File upload** → `app/parsers/<vendor>.py` (FortiGate, Check Point, Palo Alto,
  Cisco ASA, Huawei USG) → returns `(rules, objects, warnings)`.
- **Live sync** → `app/connectors/<vendor>.py` pulls via the vendor API/SSH, then
  `app/connectors/live_sync.py` translates it (`_fgt_translate`, `_cp_translate`,
  `_huawei_translate`, and `translate()` for Palo Alto / Cisco ASA).

Both write into the same tables (`firewall_rules`, `firewall_objects`,
`object_members`, `firewall_policies.nat_rules`) and then call
`engine.run_analysis(policy_id)`.

## 2. The normalized model

After ingestion every rule/object looks the same regardless of vendor:

**Rule** — `rule_id`, `rule_name`, `section`, `rule_number`, `sources[]`,
`destinations[]`, `services[]`, `applications[]`, `source_interfaces[]`,
`destination_interfaces[]`, `action` (accept/deny), `enabled`, `logging_enabled`,
`nat_enabled`, `schedule`, `comments`, `hit_count`, `last_hit`, `first_hit`.

**Object** — `object_name`, `object_uid`, `object_type` (host/network/range/
group/service/service-group/fqdn/wildcard/…), `value`, `protocol`,
`port_start/port_end`, `members[]`, `raw_data`.

**NAT rule** (vendor-agnostic) — `nat_type` (static/destination/source/hide),
`original_src/dst/service`, `translated_src/dst/service`, `enabled`.

**Normalizer** (`analysis/normalizer.py`) turns names/UIDs into resolved values:
- `build_object_map()` keys objects by **name AND uid** (Check Point rules
  reference by name, group members often by UID).
- `expand_address_object()` / `expand_service_object()` recurse through groups.
- `is_any()` treats `any`, `all`, `any4`, `any6`, `0.0.0.0/0`, `::/0` as Any.
- `classify_ip()` → private / public / loopback / link-local / reserved.

## 3. Vendor-agnostic detectors (the engine)

`engine.run_analysis()` loads the policy's rules + objects, scores every rule
(`risk_scorer.py`), then runs the detectors below. Each emits findings with
`severity` (Critical/High/Medium/Low/Informational), `confidence`
(High/Medium/Low — reflects data completeness), evidence, and a read-only
recommendation.

**Rule security**
- `any_to_any_allow` — enabled allow with Any src **and** dst **and** service → Critical (dedicated, evidence-rich).
- `overly_permissive` — partial Any (src/dst/service); graded Critical→Medium. L7 app-constrained rules are excluded.
- `risky_service` — RDP/SSH/Telnet/SMB/SQL/VNC/etc.
- `cleartext_service` — Telnet/FTP/HTTP and other unencrypted protocols.
- `inbound_from_internet` — untrusted/public source → internal destination.
- `lateral_movement_risk` — broad internal segment → broad internal segment.
- `vpn_access` — VPN rules with overly broad access.

**Rule hygiene / lifecycle**
- `disabled_rule`, `zero_hit_rule` (only when hit-count data exists),
  `low_usage_rule`, `expired_rule`, `temporary_rule` (name/comment keywords),
  `no_logging`, `no_documentation`, `naming_quality`, `nat_complexity`,
  `negated_object`.

**Policy structure**
- `duplicate_rule`, `shadowed_rule` (full/partial, order-aware),
  `mergeable_rules`, `rule_order_optimization`, `large_rule_section`,
  `no_cleanup_rule`.

**Object hygiene**
- `unused_object` (aggregated into one finding listing all unused objects;
  credited via direct rule refs *and* members of used groups),
  `duplicate_object`, `empty_group`, `large_group`, `broad_network`,
  `service_range`.

**Import quality**
- `import_quality` — e.g. a policy with objects but **no rules** (failed rulebase
  fetch) emits one diagnostic instead of flooding false "unused" findings.

## 4. Auxiliary analyses (data-gated)

These run **only when the underlying data exists**, otherwise they degrade to
"not available" / Informational rather than fabricating findings.

| Module | Needs | Produces |
|---|---|---|
| `nat_exposure.py` | `policy.nat_rules` + rules | NAT mapping checks (DNAT/SNAT/static, duplicate/overlap, NAT-without-policy), public-exposure inventory, RDP/SSH/SMB/DB/Any public-exposure findings |
| `interfaces.py` | device interface JSON | public/WAN/mgmt interface classification, public-IP inventory, `mgmt_on_public_interface` |
| `version_intel.py` | device `os_version` + Version Catalog | outdated / end-of-support / HA-mismatch / unknown-version advisories |
| `cve_checker.py` | device `os_version` + NVD reachable | CVE lookup per OS version (CPE-mapped) |

## 5. Per-vendor specifics

The detectors are identical across vendors. What differs is **ingestion,
normalization, and which data each vendor exposes**.

### FortiGate
- **File**: full `.conf` and JSON config exports. **Live**: FortiOS REST API.
- Sources/destinations/services reference named objects; `member` (singular) for
  groups. Address types: ipmask, iprange, fqdn, geo, wildcard.
- Hit counts + interfaces available from the API; serial → model mapping.
- NAT: per-rule `nat enable` flag (`nat_enabled`); central NAT not yet
  normalized into `nat_rules`.

### Check Point
- **File**: JSON policy package export. **Live**: Management API (R80+).
- Pulls per-type objects (`show-hosts/networks/groups/service-*`), the
  **access rulebase per layer**, NAT rulebase, gateways, time/app objects.
- Quirks handled:
  - Group members come as full objects, `{name,uid}` refs, **or** bare UID
    strings — resolved against a name+uid map.
  - Groups appear in both `show-groups` (with members) and the rulebase inline
    object-dictionary (summary, no members); the summary must not overwrite the
    populated group.
  - Some management versions **500 on `details-level: full`**; the rulebase fetch
    degrades full+hits → standard+hits → full → standard so rules and hit counts
    still come through.
  - "Any" object, `any4/any6`, and management/API-version vs gateway-OS-version
    distinctions are normalized.

### Palo Alto Networks (PAN-OS)
- **File**: PAN-OS XML config export. **Live**: XML API.
- Security rules with zones (`source_interfaces`/`destination_interfaces`),
  applications (App-ID) and services; address/service groups expanded.
- `application-default` services treated as opaque (App-ID enforced).

### Cisco ASA
- **File**: running-config export. **Live**: SSH/CLI.
- Access-lists → rules; object-groups (network/service) → groups; `any4`/`any6`
  normalized to Any. NAT (object/twice NAT) parsed where present.

### Huawei USG
- **File**: config export. **Live**: SSH (`huawei_ssh.py`).
- Security policies with zones; address-sets/service-sets → groups.

## 6. Confidence & data completeness

Confidence is **not** cosmetic — it encodes how much evidence backs a finding:
- **High** — complete parsed rule/object/NAT/interface/version evidence.
- **Medium** — partial mapping or inferred exposure (e.g. NAT-published service
  with no corroborating security rule).
- **Low** — missing objects, NAT, interfaces, hit counts, or version catalog.

## 7. What deliberately does NOT happen

- No write-back of any kind (rules, objects, NAT, interfaces, firmware).
- No zero-hit findings without hit-count data.
- No "unused"/"empty group" findings when rules failed to import.
- No EOL/outdated-version findings without a Version Catalog entry.
- No public-exposure findings from NAT alone without supporting evidence.
