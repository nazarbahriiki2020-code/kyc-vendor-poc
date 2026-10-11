# Run summary

Generated from `results/runs.jsonl`. Figures are **observed API round-trip latency from one machine (median / p95), not a vendor performance benchmark** and not end-user verification time. Get-decision figures are polling calls: many calls can belong to the same session.

| Vendor | Create session | Get decision: poll calls | Sessions polled | Scenario runs (match) | Errors | Webhooks ok / duplicate / rejected |
| --- | --- | --- | --- | --- | --- | --- |
| didit | 250 / 632 ms (n=11) | 266 / 540 ms (n=56) | 10 | 7/8 | 1 | 0 / 0 / 0 |
| veriff | 738 / 738 ms (n=1), too few to compare | 249 / 744 ms (n=92) | 1 | 0/0 | 0 | 0 / 0 / 0 |

## Scenario matrix

| Vendor | Scenario | Expected | Actual | Match | Risk codes |
| --- | --- | --- | --- | --- | --- |
| didit | `approve` | approved | approved | ✅ | – |
| didit | `decline_document_expired` | declined | declined | ✅ | – |
| didit | `decline_mrz_validation` | declined | declined | ✅ | – |
| didit | `decline_face_match_low_similarity` | declined | declined | ✅ | – |
| didit | `decline_liveness_attack` | declined | declined | ✅ | – |
| didit | `decline_ip_blocklist` | declined | declined | ✅ | – |
| didit | `review_face_match_borderline` | review | declined | ❌ | – |
| didit | `decline_aml_hit` | declined | declined | ✅ | – |

## Errors

| Vendor | Step | HTTP | Message |
| --- | --- | --- | --- |
| didit | create_session | 403 | [didit] create session failed (HTTP 403): {"detail":"You do not have permission to perform this action."} |
