# PolicyInsight Analysis Accuracy Model

PolicyInsight is **strictly read-only**. It never writes, disables, reorders, or
remediates firewall configuration. This document defines the analysis model the
engine targets so that findings are conservative, evidence-based, and vendor-aware
— comparable to the cleanup logic of Tufin SecureTrack, AlgoSec, FireMon, Skybox,
and Palo Alto Policy Optimizer. It complements [analysis-vendor-semantics.md](analysis-vendor-semantics.md)
(per-vendor evaluation context).

## 1. How mature tools classify cleanup findings
- **Tufin SecureTrack** Cleanup Browser (verified against Tufin docs, R25-2). Its
  categories split cleanly into **configuration-derived** and **traffic-derived**:
  - Config-only: *C01 fully shadowed & redundant rules*, *C05 disabled rules*,
    **C06 unattached network objects** ("objects not appearing in firewall
    rules"), *C08 empty groups*, *C11 duplicate network objects*,
    *C12 duplicate services*.
  - Traffic-log-dependent: **C15 unused network objects** — "no hits in the
    policy traffic log during the time period configured" (the period — days /
    weeks / months — is operator-selected). Cleanups are configurable
    (name / severity / definition).
  - **We follow this split exactly.** Our config-derived object finding is named
    `unattached_object` (= Tufin C06); the traffic-based "unused object" (C15) is
    intentionally **not** emitted because PolicyInsight does not ingest per-object
    traffic logs (documented limitation, not a false negative).
  - **Deliberate divergence:** Tufin merges *shadowed* and *redundant* into one
    category (C01). We instead **split** them (`shadowed_rule` for a different
    effective action vs `redundant_rule` for the same action) and add
    `inoperative_rule`, following FireMon's
    finer-grained model below. Both are config-derived from rule containment.
- **AlgoSec**: an object is **unattached** only if it is *not used in any rule* **and**
  *not a member of any group used in a rule* — matches Tufin C06 and our graph.
- **FireMon** removable-rules report separates **shadowed**, **redundant**, and
  **inoperative** rules as distinct findings (the model we adopt for rules).
- **Palo Alto Policy Optimizer** separates **rules without app controls**,
  **unused apps in a rule**, and **unused rules**.

## 2. Finding vocabulary (must stay distinct)
| Term | Meaning | Data required |
|---|---|---|
| **unattached object** | Not referenced by any rule/NAT and not a member of any used group | Complete object reference graph |
| **unused object in rule** | Present in a rule/group but traffic logs show no use in the period | Per-object usage/log data |
| **redundant rule** | Earlier rule covers the same traffic with the **same** action | Full expansion + comparable context |
| **shadowed rule** | Earlier rule covers the traffic with a **different effective** action (later rule unreachable) | Full expansion + order + context |
| **partial shadow** | Only part of the later rule's traffic is covered | Full expansion + context |
| **inoperative rule** | Cannot match: empty/impossible/intersecting conditions | Full expansion |
| **over-permissive** | Any/Any/Any or near-Any enforced allow | Enabled + enforced + effective-Any |

> Implementation note: the engine emits `redundant_rule` (same action, fully
> covered), `shadowed_rule` (different effective action, unreachable),
> `partial_shadowed_rule`, `inoperative_rule`, and `shadowing_not_evaluated`
> (= shadow analysis not available). The earlier `same_action_shadowed_rule` /
> `conflicting_shadowed_rule` names are retained only as render aliases for
> historical findings. The **model** matches the table above.

## 3. Object usage rules
An object is **used** if referenced from any of:
1. Security rules (source/destination/service/application/user/vpn).
2. NAT rules (original/translated source/destination/service).
3. Address groups, 4. Service groups, 5. Application groups.
6. URL/application categories (where parsed).
7. VPN communities/objects (where parsed).
8. Routes/interfaces (where parsed).
9. Local-in / management-plane policies (where parsed).
10. Vendor automatic-NAT references (where parsed, e.g. FortiGate VIP `mappedip`).
11. Policy layers / inline layers (where applicable).

## 4. Group membership usage rules
1. A group used in a rule is **used**.
2. Every member of a used group is **indirectly used**.
3. Nested group members are indirectly used (recursive).
4. Recursive expansion must **detect circular references** and terminate safely;
   a detected cycle is reported as an informational diagnostic, never as "unused".
5. **Built-in/predefined** vendor objects are **system objects** — excluded from
   unused/empty/name-quality cleanup unless explicitly mis-referenced.
6. **Unknown/unresolved** objects are **not** treated as unused.
7. If object import is incomplete, **suppress** unattached findings and emit an
   `object_usage_unknown` import-quality diagnostic instead.

## 5. Application Control analysis rules (vendor-aware)
- **Check Point**: the Services & Applications column may mix services,
  applications, mobile apps, websites, default & custom categories. Preserve them
  **separately**; analyze within the App-Control/URL layer; never collapse to a
  generic service list; never report "Any service" when the real issue is
  "Application Any" or "No Application Control".
- **Palo Alto**: distinguish `application:any`, `service:any`,
  `service:application-default`, specific apps, URL categories, User-ID. Optimizer
  categories: Rules-Without-App-Controls, Unused-Apps-in-Rule, Unused-Rules,
  Port-Based-Rule-Candidate, Over-Provisioned-Application-Rule. `application:any`
  **with a restricted service** is **not** Any/Any/Any.
- **FortiGate**: App-Control is a **security profile** attached to a policy, **not**
  a match field — never treat it like Palo App-ID. Detect: profile absent where
  expected, broad allow with no profiles, profile present but unexpandable, data
  unavailable, SSL-inspection unknown.
- **Huawei**: application/app-groups only if parsed; otherwise informational note.

## 6. Vendor-specific rule context
Rules are only compared (shadow/redundant/duplicate) within the same evaluation
context: FortiGate interface-pair/VDOM; Check Point package/layer/inline-layer/
install-target; Palo Alto pre/local/post + zones/device-group; Cisco ASA ACL +
interface/direction; Huawei source/destination zone + sequence. See
[analysis-vendor-semantics.md](analysis-vendor-semantics.md).

## 7. Detector prerequisites
Each detector declares required data and **missing-data behavior** (skip / reduce
confidence / informational diagnostic). Implemented as a code matrix in
`app/analysis/prerequisites.py` (see Phase 2). Examples: zero-hit ⇒ real hit-count
source; low-usage ⇒ last-hit; duplicate/shadow ⇒ full expansion + comparable
context; public exposure ⇒ public IP/interface/NAT + policy evidence; unattached
object ⇒ complete reference graph; version EOL ⇒ version catalog; App-Control ⇒
vendor-supported application data.

## 8. Confidence model
- **High** — all prerequisites met, objects fully expanded, context known.
- **Medium** — derived/correlated signal, or partial corroboration.
- **Low** — heuristic, or some inputs unresolved.
Missing prerequisites lower confidence or suppress the detector; they never raise
severity.

## 9. Import quality gates
Before detectors run, completeness is assessed (rules, objects, group expansion,
NAT, interfaces/zones, hit-counts, last-hit, application data, version data,
parser warnings). A detector depending on missing data is suppressed or
downgraded per the prerequisite matrix. **No high-severity finding is produced
from incomplete data.**

## 10. False-positive prevention rules
1. Never flag an object used through a group (direct/nested) as unattached.
2. Never flag unknown/unresolved objects as unused.
3. Never emit unattached findings when the object graph is incomplete — diagnose.
4. Never compare rules across unrelated layers/interfaces/zones/install targets.
5. Never treat a disabled rule as active for shadow/over-permissive.
6. Never derive a usage-based finding (zero-hit, unused-in-rule) without usage data.
7. Never derive public exposure from NAT alone — require policy + interface/IP.
8. Never treat `application:any` + restricted service as Any/Any/Any.
9. Never treat a FortiGate security profile as a match field.
10. Built-in/system objects are excluded from hygiene cleanup by default.
