# dev-newui audit and phased delivery plan

Audit date: 2026-09-14. Scope: the local `dev-newui` checkout and its checked-in deployment configuration. The working tree was clean before this phase. The running deployment, production secrets, database contents, and device behavior were not accessible, so this is a repository audit rather than a production certification.

## Current architecture and implemented inventory

| Boundary | Current implementation | Important limit |
|---|---|---|
| Import | `api/upload.py`, five `parsers/` adapters, five `connectors/` adapters | Parsers return untyped rule/object dictionaries and warnings; unsupported syntax can survive as an apparently usable rule. |
| Storage | SQLAlchemy models and seven Alembic revisions; customer, device, policy, rule, object, analysis run, finding, review comment, report tables | No engagement/project entity, immutable source checksum, normalized source-location table, or first-class telemetry series. Uploaded raw files are referenced by path. |
| Analysis | `analysis/engine.py` orchestrates scoring, prerequisites, duplicate/shadow, exposure, NAT, object and hygiene checks | Matching semantics remain spread across detectors; the model does not represent all vendor-specific match behavior. |
| API/security | FastAPI routers, session identity, capability checks, customer access, audit log, upload size/type guards | Authorization must be checked endpoint by endpoint; background tasks have no durable queue or cancellation. |
| UI | React/Vite pages for customers, upload, devices, policies, findings, review, reports, audit and change watch | Review and import quality exist, but findings do not yet carry the complete classification/evidence contract in the brief. |
| Reporting | Shared report data and HTML/PDF/DOCX/XLSX/CSV/JSON exporters | Reproducibility from an immutable analysis snapshot must be verified; current run/finding records are mutable. |
| Deployment | Docker Compose: PostgreSQL 16, FastAPI, nginx; Alembic on backend startup; SSH update workflow | Checked-in CI deploy workflow covers `DEV`/`PROD`, not `dev-newui`, and does not run tests before deploy. Running host configuration was not inspected. |

Data flow: uploaded file or connector response -> vendor parser/translator -> `FirewallPolicy`, `FirewallRule`, `FirewallObject` and raw JSON fields -> `normalizer.py` expansion -> `engine.run_analysis()` -> `Finding` and `AnalysisRun` -> API -> React UI and report exporters. The persisted rule fields include order, zones/interfaces, services, applications, users, VPN, schedule, action, logging, NAT flag and hit data. They do **not** prove the vendor's complete traffic-match semantics; for example NAT stage, identity resolution, default rules, advanced schedules and policy-layer execution can remain opaque.

## False-positive root causes and this phase's corrections

| Trigger | Before | This phase |
|---|---|---|
| Same address/port/action but different application, user, VPN, schedule or inspection behavior | Duplicate or redundant finding could be emitted | Shared rule comparison guard rejects the pair; `engine._rule_to_dict` now passes persisted user/VPN fields through. |
| Two of source/destination/service contained but the third disjoint | `partial_shadowed_rule` could be emitted despite no common traffic | Partial findings require overlap in all three dimensions. |
| Two unresolved empty groups | Vacuous equality/containment could look like a confirmed duplicate/shadow | Empty or unresolved expansions are excluded from definitive pair comparison. |
| Earlier TCP all-ports service, later any-protocol service | Protocol wildcard on the inner service was incorrectly treated as contained | Containment now requires the outer protocol to be `any` or the protocols to agree. |
| `any4` compared with `any6` | The current normalizer maps both to an IPv4 wildcard, allowing a false duplicate/shadow | Definitive comparisons involving explicit address-family markers or IPv6 values are suppressed pending a typed dual-stack model. |
| Zero hit counter on an old imported policy | Could claim the rule had “never” matched, despite unknown counter period or reset | Usage findings require explicit complete, current, reset-free per-rule `usage_observation` metadata; zero hits are framed as review only. Existing importers do not supply this provenance, so usage findings are suppressed until telemetry collection is implemented. |

The above fixes avoid unsafe assertions but are deliberately conservative: they can miss valid cleanup opportunities. An exact match of names in opaque application/identity fields is **not** proof of semantic equivalence. Finding confidence must be downgraded once these fields have an explicit completeness state.

## Coverage matrix (repository evidence, not vendor certification)

| Vendor | File input | Live connector | Major semantic gaps to validate |
|---|---|---|---|
| FortiGate | `.conf`, `.txt`, `.json`, `.cfg` | FortiGate connector | Central NAT, local-in, identity and profile coverage, VDOM and install target semantics. |
| Check Point | `.json`, `.txt` | Check Point connector | Inline layers, access roles and URL category typing, install-target overlap, NAT ordering. |
| Palo Alto | `.xml` | Palo Alto connector | Local/pre/post scope, App-ID and `application-default`, User-ID, post-NAT zone. |
| Cisco ASA | `.txt`, `.conf`, `.cfg` | Cisco ASA connector | ACL binding and direction, object/NAT order, inactive rules, implicit security levels. |
| Huawei USG | `.txt`, `.cfg`, `.conf` | Huawei connector | Zone order, application/identity, destination NAT original-packet fields. |

The parsers and connectors exist; the matrix does not imply full version or syntax support. `docs/analysis-vendor-semantics.md` records known gaps, but some statements there describe intended rather than verified behavior. Each adapter needs versioned fixtures and explicit unsupported-construct diagnostics before it may certify a full analysis.

## Prioritized backlog and acceptance gates

Effort is an estimate in engineering days for one engineer, excluding access to vendor fixtures and customer review. Risk describes implementation risk.

| Phase | Work and dependency | Effort / risk | Acceptance criteria |
|---|---|---|---|
| 1. Baseline and false-positive controls | Audit, adversarial fixtures, conservative duplicate/shadow/usage gates (this phase) | 3-5 / medium | Reproduced cases have failing-before/passing-after tests; backend and frontend build pass. |
| 2. Source lineage and parser validation | Depends on vendor/version examples; hash raw inputs, record line/object source locations, reject or quarantine unsupported constructs | 8-15 / high | Every normalized entity links to source; malformed and unsupported constructs create visible diagnostics; no silent confident findings. |
| 3. Canonical policy and formal matching | Depends on phase 2; typed IPv4/IPv6 sets, ranges, negation, protocols, application/identity, schedule, NAT stage, layers and default behavior | 15-30 / high | Golden/adversarial tests for first-match order, mixed actions, combinations, IPv6, NAT, cycles, schedules and witnesses; no cross-context claims. |
| 4. Evidence and review contract | Depends on phase 3; explicit classification, stable finding keys, confidence rationale, uncertainty, impact, validation and rollback fields | 8-14 / medium | Every finding validates against schema and exposes lineage plus false-positive reason; review history is immutable. |
| 5. Persistence/API/jobs | Depends on phases 2-4; engagement scoping, snapshot IDs, tenant checks, durable idempotent jobs, progress/retry/cancel, migrations | 12-20 / high | Tenant tests, migration rehearsal on backup, restart/retry tests; existing data preserved. |
| 6. Engineer workflow and reports | Depends on 4-5; data-quality gate, comparison/evidence UI, bulk review safeguards, deterministic report snapshot | 12-20 / medium | Upload-to-review-to-report UI test; six exporters agree on one frozen run and label observation vs approval vs completion. |
| 7. Performance and security hardening | Depends on representative sanitized datasets; profile parser, comparison, queries and report generation; audit auth, CSRF, uploads, dependencies and deployment | 8-16 / medium | Published fixture sizes, runtime/memory/query budgets, benchmark trend; security-critical issues closed or explicitly accepted. |

Do not use the current findings as approved change instructions. No automatic firewall change or deployment is added in this phase.

## Data, operations and validation notes

Reanalysis now commits finding replacement, rule scores and completion metadata in one transaction. Detector or database failures roll back the replacement, preserving the previous findings, reviewer comments and scores, while recording the failed run separately. Successful reanalysis still replaces findings and comments: immutable review history and stable finding reconciliation remain phase 4 work.

The scorecard uses the analysis reference graph for non-service object hygiene, including nested groups, relational membership and NAT references. Missing references, cycles, absent rules or no eligible objects make the dimension unavailable and remove its weight. Counts describe unattached objects in the imported configuration, not confirmed runtime non-use. Temporary-rule keywords use the same whole-token matching as analysis. Duplicate-object value comparisons still need type/protocol-aware semantics.

The current relational model links `Finding` to `AnalysisRun` and policy, with JSON evidence and workflow status. It does not have a standalone recommendation classification or immutable report-source snapshot. Preserve all existing rows when extending the schema; add nullable columns or new tables first, backfill, validate, then tighten constraints. Keep customer scope on every query and report lookup.

The first phase needed no migration. The subsequent import-lineage increment adds nullable `firewall_policies.source_sha256` and `parse_warnings` columns in revision `e7f9b2c4d6a8`. New file uploads store the SHA-256 of the exact raw bytes and a `source_ref` with checksum, collection and record index in each imported rule/object's `raw_data`. Older policies retain nulls; they are not silently assigned a checksum for a file that may have changed. Exact source line numbers and source checksums for live connectors remain future work. The source file remains in the existing upload volume.

A verified usage observation must contain `start`, `end`, `complete: true`, `counter_reset: false`, and a source, with at least `USAGE_OBSERVATION_DAYS` elapsed and an end within seven days. No importer currently generates such metadata; zero/low-hit findings and usage-based risk scoring are suppressed until a collector can prove it. The scorecard labels usage as unavailable and excludes its weight when telemetry is unverified. Policy age is not counter age.

Palo Alto file import now accepts XML only, matching the actual parser. JSON/CLI exports were previously offered in the upload UI but the parser rejected them. Unsupported formats are rejected before persistence. UTF-8 decoding is strict so damaged policy bytes are not replaced silently. Policy files cannot supply trusted usage-observation metadata: that field is stripped from imported rule data and a warning is retained. Parser warnings and the raw source checksum are available from the policy API; warning-specific suppression of every detector remains to be implemented.

Local commands from repository root (Windows PowerShell):

```powershell
.\setup.ps1
.\start.ps1 -SeedDemo
.\.venv\Scripts\python.exe -m pytest backend/tests/ -q
cd frontend
npm.cmd test
npm.cmd run build
```

Migration in an already configured backend: `cd backend; ..\.venv\Scripts\python.exe -m alembic upgrade head`. Production deployment remains the documented `docker compose up -d --build` workflow in `DEPLOY.md`, after database backup and staged migration. No production deployment or database migration was performed during this audit.

Benchmark baseline and precision/recall are **not established**: the repository has small sample exports but no labeled enterprise corpus. The next phase must obtain sanitized labeled examples, track false positives/negatives, and profile representative 1k/10k/100k-rule policies before setting an enterprise performance budget. Do not invent accuracy or scale claims from the unit tests.
