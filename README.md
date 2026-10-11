# KYC Vendor PoC: Didit vs Veriff

A Python proof-of-concept that integrates two identity-verification (IDV) vendors behind one interface, runs them end-to-end in test mode, and turns the observations into a vendor scorecard and a recommendation.

## Contents

1. [Executive summary](#executive-summary)
2. [Goal](#goal)
3. [Business case](#business-case)
4. [Architecture](#architecture)
5. [Data model and personal data](#data-model-and-personal-data)
6. [Setup](#setup)
7. [How to test](#how-to-test)
8. [Results](#results)
9. [Findings](#findings)
10. [Trade-offs and design decisions](#trade-offs-and-design-decisions)
11. [Vendor scorecard](#vendor-scorecard)
12. [Evidence vs vendor claims](#evidence-vs-vendor-claims)
13. [Recommendation](#recommendation)
14. [Known limitations](#known-limitations)
15. [Possible improvements](#possible-improvements)
16. [Project structure](#project-structure)

## Executive summary

- **Finding.** In the tested scenarios, Didit offered a far more testable sandbox: 7 of 8 automated scenarios matched the expected outcome, and a real hosted run returned a per-check result with a machine-readable reason (`DOCUMENT_EXPIRED`). Veriff's test mode cannot produce decisions on its own; they are set by hand.
- **Decision.** Didit is the preferred candidate for the next evaluation stage, based on developer experience and sandbox testability. **This is not yet a recommendation for production adoption.**
- **Open risks.** Not yet confirmed for either vendor: real-world fraud-detection accuracy, Southeast Asia document and eID coverage, data retention terms, production onboarding and pricing, and end-to-end webhook delivery.

## Goal

Show how to go from an identity-verification question to evidence: pick vendors, integrate their APIs from documentation alone, test them hands-on, and separate what was verified from what the vendor claims.

The PoC deliberately looks beyond the happy path: failed checks, configuration that changes outcomes, errors that hide their cause, webhook replays, and personal data leaking into logs.

## Business case

A product team building identity verification has to choose IDV vendors. Before any commercial talks, they need answers to practical questions:

- How long does it take an engineer to get a first verification working?
- Can the integration be tested automatically, without real identity documents?
- When a verification fails, does the API say which check failed and why?
- What does the vendor do with test data?

This PoC answers those questions for two self-serve vendors, **Didit** and **Veriff**, using a standard flow: document capture + liveness + face match, through each vendor's hosted web flow.

## Architecture

```
                        ┌──────────── same calling code ────────────┐
  CLI (create, watch,   │                                            │
  bench, summary) ──────┼──► KYCVendor interface                     │
                        │      ├─► Didit adapter  ──► Didit API v3   │
                        │      └─► Veriff adapter ──► Veriff API v1  │
                        └────────────────────────────────────────────┘
                                         │ normalised, PII-free results
                                         ▼
                                results/runs.jsonl ──► results/summary.md

  Vendor ──► webhook ──► FastAPI receiver ──► verify signature ──► de-duplicate ──► results/runs.jsonl
  End user ──► vendor-hosted flow (document, selfie) ──► vendor decides ──► polling or webhook
```

Two independent ways to learn a decision:

- **Polling** (`watch`): calls the vendor's decision endpoint until the status is final. Used for all runs in this PoC.
- **Webhooks** (`serve`): the vendor pushes status changes; the receiver authenticates and de-duplicates them. Implemented and unit-tested, not yet tested end-to-end.

The end user never touches our code: documents and selfies go straight to the vendor's hosted flow, so this application never handles images.

## Data model and personal data

Each vendor's statuses are mapped to one internal enum, so results can be compared directly. The vendor's original status string is kept next to it.

| Internal status | Didit | Veriff |
| --- | --- | --- |
| `pending` | Not Started, In Progress, Awaiting User | no decision yet |
| `approved` | Approved | approved |
| `declined` | Declined | declined |
| `review` | In Review | review |
| `resubmit` | Resubmitted | resubmission_requested |
| `expired` | Expired, Kyc Expired | expired |
| `abandoned` | Abandoned | abandoned |

A decision is stored as a list of checks (`id_verification`, `liveness`, `face_match`, ...), each with a status, an optional score and risk codes.

**Personal data.** PII is excluded from persisted evidence and application logs by design, and raw vendor responses are not persisted:

- Decision payloads do contain PII (names, dates of birth, document numbers). The code receives them in memory and keeps only statuses, scores and risk codes when mapping to the internal model. Tests assert that names and dates of birth from sample payloads do not appear in the output.
- Vendor **error** bodies are reduced to an allow-list of fields (`detail`, `message`, `error`, `code`, `reason`, `status`). Anything else, including non-JSON error pages, is dropped before it reaches exceptions or logs. Tests cover both cases.
- The only identifier sent to vendors is a random reference (`poc-xxxxxxxxxx`).
- `results/runs.jsonl` contains session URLs. A Veriff session URL is a signed token valid for 7 days, so the file is git-ignored and stays local. Only `results/summary.md` is published.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q                                              # 32 passed, no keys needed
cp .env.example .env                                   # then fill in the keys below
```

**Didit** (self-serve, no sales call)
1. Sign up at [business.didit.me](https://business.didit.me).
2. Turn on **Test mode** (application switcher, top-left). Test-mode sessions are free, call no real providers and offer sample documents. The hosted flow shows a **SANDBOX** banner on every screen.
3. Test mode and live mode have **separate API keys and workflows**. With Test mode on, copy:
   - **Workflows** → ID of a KYC workflow (this PoC used *Free KYC*: ID + liveness + face match + IP analysis) → `DIDIT_WORKFLOW_ID`;
   - **API Keys** → the full key is shown only once, so rotate it if needed → `DIDIT_API_KEY`.

**Veriff** (self-serve trial)
1. Sign up via the [Self-Serve plan page](https://veriff.com/plans/self-serve). Before trial access is granted, **you verify your own identity** with a real ID and a selfie.
2. In Veriff Station, **Workspace → Integrations**, create an integration of type **Test**.
3. Copy the **API key**, **shared secret** and **Base URL** into `.env`.

## How to test

```bash
# 1. Automated scenario matrix (Didit test mode): create → force outcome → poll
python -m kyc_poc bench didit

# 2. Real hosted run with a sandbox scenario (Didit)
python -m kyc_poc create didit --scenario decline_document_expired
python -m kyc_poc watch didit <session_id>
#    open the URL, use a sample document from the strip under the upload area, take a selfie

# 3. Real hosted run (Veriff Test integration)
python -m kyc_poc create veriff --callback https://example.com/done
python -m kyc_poc watch veriff <session_id>
#    complete the flow, then in Station open the session → Update decision

# 4. Summary table
python -m kyc_poc summary

# Optional: webhook receiver
python -m kyc_poc serve            # http://127.0.0.1:8000/webhooks/{didit|veriff}
ngrok http 8000                    # register the public URL in each vendor console
```

What to check:

- `bench` prints `ok` for each scenario whose final status matches the expected one.
- `watch` prints every status change and then the per-check decision with risk codes.
- `results/summary.md` contains no names, dates of birth or document numbers.

## Results

Runs made on 8–11 Oct 2026 from one machine in Ukraine. Raw numbers: [`results/summary.md`](results/summary.md).

### API behaviour

These are **observed API round-trip latencies from one machine, not a vendor performance benchmark.** Get-decision figures are polling calls, and many calls belong to the same session.

| Metric | Didit | Veriff |
| --- | --- | --- |
| Create session, median / p95 | 250 / 632 ms (11 calls) | 738 ms (1 call, too few to compare) |
| Get decision: polling calls, median / p95 | 266 / 540 ms (56 calls) | 249 / 744 ms (92 calls, all for one session) |
| Automated scenarios matching the expected outcome | **7 / 8** | n/a: no scenario API |
| Who decides in test mode | Didit, from the armed scenario | A person, in Station (**Update decision**) |
| Sample test documents | Built in (Spain ID, Argentina passport, Poland licence) | None: a real document is required |
| Webhooks tested end-to-end | No | No (Station shows event webhooks delivered) |

### Didit scenario matrix

| Scenario | Expected | Actual | Match |
| --- | --- | --- | --- |
| `approve` | approved | approved | ✅ |
| `decline_document_expired` | declined | declined | ✅ |
| `decline_mrz_validation` | declined | declined | ✅ |
| `decline_face_match_low_similarity` | declined | declined | ✅ |
| `decline_liveness_attack` | declined | declined | ✅ |
| `decline_ip_blocklist` | declined | declined | ✅ |
| `review_face_match_borderline` | review | declined | ❌ (see finding 1) |
| `decline_aml_hit` | declined | declined | ✅ (see finding 2) |

### Same case on both vendors: decline because of the document

| | Didit | Veriff |
| --- | --- | --- |
| How the decline was produced | Hosted flow with a sample document, scenario `decline_document_expired` | Hosted flow with a real document, decision set by hand |
| Statuses seen by polling | Not Started → In Progress → Declined | no decision → declined |
| Decision returned by the API | One result **per check**: `id_verification: Declined (DOCUMENT_EXPIRED)`, `liveness: Approved (99)`, `face_match: Approved (95)`, `ip_analysis: Approved` | One **overall** result: `declined`, `code 9102 Suspected document tampering` |
| Flow start → decision | 48 s | ~4 min to submit; the decision was manual, so not comparable |

## Findings

1. **Workflow configuration changes outcomes, not only the vendor.** Didit's `review_face_match_borderline` scenario ended `Declined`, not `In Review`. Didit's docs say a sandbox session lands in review only when the workflow routes it there, and the *Free KYC* workflow has no review branch for face match.
2. **Forcing an outcome is not the same as running the checks.** Didit's `simulate` endpoint set `Declined` for `decline_aml_hit` although the workflow has no AML step, and simulated sessions carried no risk codes. Risk codes appeared only after completing the hosted flow. So the scenario matrix tests status handling, and the hosted run tests the checks.
3. **Didit explains declines per check; Veriff returns one reason.** Didit returned a status and score for every check plus a risk code. Veriff (test mode, manual decision) returned an overall status with a numeric code and a reason from a fixed list (fraud, document, IP, velocity/abuse). Whether Veriff returns per-check detail on live sessions was not verified.
4. **Errors from mixed environments are vague.** A live-mode Didit key used with a test-mode workflow returned `403 "You do not have permission to perform this action."`, with no hint that the two belong to different environments.
5. **Developer onboarding differs a lot.** Didit: self-serve, no identity check, first successful API call in the first evening. Veriff: self-serve trial, but the developer must first pass KYC with a real ID, and the 15-day trial clock starts at signup.
6. **Test data is kept for two years.** Veriff Station showed that a test session, including document images, is deleted on **10 Oct 2028** unless removed earlier. Didit's retention for sandbox media was not checked.
7. **End-user UX details.** Didit's decline screen does not say why, which is normal in KYC so that fraudsters are not coached. Without a `callback`, Veriff sends the user to a Veriff marketing page after the flow, so a callback is required in a real integration.

## Trade-offs and design decisions

Each item below is a deliberate choice, with what it costs.

### 1. One adapter interface instead of vendor SDKs

Both vendors are called over plain HTTP through one `KYCVendor` interface (`create_session`, `get_decision`, `verify_webhook`, `parse_webhook`). Differences in results therefore come from the vendors, not from different glue code, and adding a third vendor means writing one adapter. Cost: vendor SDK conveniences, such as embedded web components, are not used.

### 2. Hosted flows instead of standalone APIs

Both vendors also offer APIs that accept document images directly. The PoC uses their hosted flows instead, so the application never handles document images or selfies, and the vendors' own capture and liveness UX is part of what gets evaluated. Cost: less control over the user experience.

### 3. Polling first, webhooks second

Every run used polling because it needs no public URL and is easy to debug. Both vendors recommend webhooks for production, so a signature-checking receiver is included. Cost: webhook behaviour is covered by unit tests only, not by real deliveries (see limitations).

### 4. Webhook authentication and replays

- **Didit:** the receiver accepts `X-Signature-V2`, which is HMAC over canonical JSON and survives framework re-encoding, or `X-Signature` over raw bytes. It rejects requests older than 5 minutes. It deliberately does **not** accept `X-Signature-Simple`, because, per Didit's docs, that header does not cover the decision body.
- **Veriff:** HMAC-SHA256 of the raw body with the integration's shared secret and, when the header is present, a check that it carries our API key. No timestamp is checked.
- **Replays and retries:** an authenticated event is processed once. The key is Didit's `event_id`, which Didit reuses on retries. Veriff decision webhooks have no event id, so the key there is session + type + status. Duplicates get `200` so the vendor stops retrying, and are logged as duplicates. Cost: the set of seen events is in memory and bounded, so a restart forgets it. Production would use a unique constraint in a database.

### 5. Normalised statuses

Mapping seven or more vendor statuses onto one enum makes vendors comparable, but loses nuance: for example, Didit's `Expired` and `Kyc Expired` both become `expired`. The raw vendor status is therefore always stored next to the normalised one.

### 6. Personal data kept out of evidence

Results store statuses, scores and risk codes only, and error bodies pass through an allow-list. Cost: when debugging, the full vendor response is not available afterwards and has to be fetched again from the vendor.

### 7. Two levels of testing

`bench` forces outcomes through Didit's simulate API: fast, repeatable, but it does not run the checks (finding 2). Hosted runs exercise the real checks but need a person and a phone. Both are kept because they answer different questions.

### 8. Score only what was tested

The scorecard leaves untested criteria empty instead of guessing. A score on 40% of the weight is less impressive than a full table, but it does not pretend to know vendor accuracy, coverage or pricing.

## Vendor scorecard

Scores 1 (poor) to 5 (excellent). Only criteria this PoC actually tested are scored.

| Criterion | Weight | Didit | Veriff | Evidence |
| --- | --- | --- | --- | --- |
| Time to first verification (self-serve, docs) | 15% | 5 | 3 | Finding 5 |
| Sandbox realism and test controls | 15% | 5 | 2 | Scenario matrix, sample documents; Veriff has neither |
| API design and error clarity | 10% | 4 | 3 | Per-check decisions (finding 3), vague 403 (finding 4); Veriff needs HMAC-signed requests and returns one reason |
| **Score over tested criteria (40% of weight)** | | **4.75** | **2.63** | |
| Webhook security and reliability | 10% | – | – | Implemented and unit-tested, not tested end-to-end |
| Feature coverage (document, liveness, face match, NFC, eID) | 15% | – | – | Needs live sessions |
| Southeast Asia document / eID coverage | 15% | – | – | [docs/sea-coverage.md](docs/sea-coverage.md), not yet filled |
| Commercial terms and production onboarding | 10% | – | – | Needs sales contact |
| Privacy, data residency, certifications | 10% | – | – | Veriff retention observed (finding 6); Didit not checked |

## Evidence vs vendor claims

Vendor marketing is a hypothesis until tested.

| Statement | Source | Status |
| --- | --- | --- |
| Didit sandbox mocks providers and is not billed | [Didit sandbox docs](https://docs.didit.me/integration/sandbox-testing) | **Verified**: test-mode sessions showed a SANDBOX banner; balance unchanged |
| Didit scenarios produce deterministic outcomes | Didit sandbox docs | **Partly verified**: 7/8 matched; the review scenario depends on the workflow (finding 1) |
| Didit returns machine-readable risk codes per check | Didit decision docs | **Verified**: `DOCUMENT_EXPIRED` on a hosted run |
| Didit `X-Signature-Simple` does not cover the decision body | [Didit webhook docs](https://docs.didit.me/integration/webhooks) | Documented; the receiver does not accept it |
| Veriff does not decide sessions in Test integrations | [Veriff developer docs](https://veriff.com/developers) | **Verified**: decision set by hand in Station |
| Veriff self-serve limit: 30 sessions per minute | [Veriff docs](https://devdocs.veriff.com/docs/how-to-generate-sessions-manually) | Documented, not tested |
| Didit: 220+ countries, 14,000+ document types | Didit marketing | **Not verified** |

## Recommendation

**Didit is the preferred candidate for the next evaluation stage, based on developer experience and sandbox testability. This is not yet a recommendation for production adoption.** The next stage should confirm webhook delivery end-to-end, measure accuracy on a labelled set of live sessions, and check Southeast Asia coverage and data retention.

**Veriff: defer until a live or sales-assisted trial.** The integration works, but test mode cannot show decision quality: decisions are manual and there are no test documents. A fair comparison needs live sessions, which require a commercial agreement.

Neither result says anything yet about fraud-detection accuracy, which is the most important production question.

## Known limitations

- Test-mode outcomes are produced by the vendor (Didit scenarios) or by a person (Veriff), so this PoC measures integration effort and API behaviour, **not** fraud-detection accuracy.
- Latency figures are API round-trips from one machine; Veriff create-session has one sample.
- One hosted run per vendor, by a first-time user, so flow durations include learning the UI.
- Webhook handling is unit-tested only. The seen-events store is in memory.
- Southeast Asia coverage comes from vendor documentation unless marked as tested.

## Possible improvements

- **End-to-end webhook test** for each vendor through a public tunnel: a valid signature, a tampered body, a wrong signature, and a redelivery of the same event.
- Persistent de-duplication (a database unique constraint on the event key).
- Live-session accuracy test on a labelled set, including spoofing attempts against liveness.
- Fill the Southeast Asia coverage table: Singpass/Myinfo, MyKad, e-KTP, PhilSys and their regulatory constraints ([template](docs/sea-coverage.md)).
- A third vendor through the same interface.
- A command that deletes test sessions on the vendor side after a run.

## Project structure

```
kyc_poc/
├── vendors/
│   ├── base.py        # KYCVendor interface + safe HTTP error handling
│   ├── didit.py       # Didit API v3: sessions, decisions, simulate, X-Signature-V2
│   └── veriff.py      # Veriff API v1: HMAC-signed requests and webhooks
├── webhooks.py        # FastAPI receiver: signature check → de-duplication → record
├── cli.py             # create / decision / watch / bench / summary / serve
├── results.py         # append-only JSONL evidence log + Markdown summary
└── models.py          # normalised, PII-free data model; error-body allow-list
tests/                 # 32 tests; vendor APIs mocked with respx, no keys needed
docs/sea-coverage.md   # Southeast Asia coverage research template
results/summary.md     # published run summary (raw runs.jsonl stays local)
```

## License

MIT
