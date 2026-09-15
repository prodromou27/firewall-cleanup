# Analyzer comparison improvements

## Reference review

Tufin's [cleanup configuration](https://forum.tufin.com/support/kc/latest/Content/Suite/cleanup_configuration.htm) distinguishes unattached objects from traffic-based unused objects, requires continuous usage coverage, and compares multiple service properties. Its [cleanup browser](https://forum.tufin.com/support/kc/latest/Content/Suite/cleanup_browser.htm) explicitly warns that omitted application criteria can produce false shadowing findings. These are useful review principles, not evidence that this application matches Tufin's capabilities. No Tufin integration or proprietary algorithm is included.

## Implemented

- Duplicate detection uses an index keyed by evaluation context, action, application/user/VPN/schedule/NAT/logging/security-profile restrictions, normalized address sets and service sets. It no longer compares every pair of rules. Duplicate group order remains deterministic in input order.
- Host and equivalent `/32` forms share a key; repeated members do not change a set. The index does not claim equivalence between arbitrary unions of subnets.
- Shadow detection computes completeness and restriction keys once per enabled rule. Unsupported rules produce an informational diagnostic, including an unsupported first or only rule.
- Both detectors reject absent match fields, negation flags, unsupported action semantics, unresolved/dynamic addresses, unsupported address families/ranges, and incomplete or invalid port bounds. Empty input fields no longer establish explicit Any matches for these detectors.
- Existing application and identity comparison gates remain in force. Existing usage findings still require verified observation metadata; ordinary imported counters are insufficient.

## Measured scope

Windows, repository Python 3.12 environment, same synthetic fixture of unique IPv4 sources, one destination and HTTPS, one measured invocation per case:

| Duplicate detector | Rules | Findings | Seconds |
|---|---:|---:|---:|
| Previous implementation (`2656934`) | 600 | 0 | 9.6544 |
| Indexed implementation | 600 | 0 | 0.0292 |
| Indexed implementation | 6,000 | 0 | 0.3022 |

Reproduce from `backend/`:

```powershell
..\.venv\Scripts\python.exe scripts/benchmark_duplicate_detection.py --sizes 600 6000
```

These timings isolate duplicate detection. They exclude parsing, other detectors, persistence and reporting. They are not an enterprise throughput or precision/recall benchmark. Shadow containment still has quadratic worst-case pair comparisons within a context; large group expansion and object graph traversal remain profiling targets. Tests assert once-per-rule gate evaluation without brittle timing thresholds.

## Remaining accuracy limits

Unsupported constructs are suppressed rather than approximated by the comparison detectors. This trades recall for fewer unsupported cleanup claims. Complete vendor modeling, source-port and other vendor service constraints, policy revision-bound telemetry, topology and NAT-stage semantics remain necessary for stronger proofs. Matching modeled fields is not authorization to remove a rule. Existing persisted findings are unchanged until policies are reanalyzed on the updated backend.
