# P-20261030-001 heartdesk: correlate trusted HTTP operation results

Implement a small pure Go package `httpclassification` and its tests. Do not change existing runtime, monitoring, UI, dependencies, workflows, or other packages. The local integrator owns those files in a separate worktree. This public task contains only generic behavior and synthetic data.

Base source: `990ea7a54e9928c9a2dcbe70b1c6ec7afb994820`. Use this instruction commit as the branch base. Read FACTS.md and REVIEW.md. Parent alone updates PROGRESS.md.

## API and wire contract

Package exports:

```go
type Event struct { TS string `json:"ts"`; RequestID string `json:"request_id"`; Method string `json:"method"`; Path string `json:"path"`; Status int `json:"status"` }
type Receipt struct { TS string `json:"ts"`; RequestID string `json:"request_id"`; Method string `json:"method"`; PathHash string `json:"path_hash"`; Status int `json:"status"`; Operation string `json:"operation"`; Outcome string `json:"outcome"` }
type Result struct { Event Event; Kind string; Operation string; ResourceHash string; Reason string }
func Classify(events []Event, receipts []Receipt, now, cutoff time.Time) []Result
```

Return one result per event in input order. Kinds: `threat`, `expected`, `integration_error`, `success`, `other`. Unmatched/malformed/ambiguous 4xx remains `threat`; non4xx remains `other`. Only matched 2xx receipt success becomes success. Input time bounds are inclusive cutoff through now+5minutes; raw and receipt timestamp skew must be <=5minutes. Nonce is lowercase hexadecimal length32, path hash lowercase SHA256 hex64. Event path must be an origin-form absolute escaped path (may include query); strip query and hash the exact escaped path bytes without cleaning/unescaping. Reject invalid escapes/absolute URLs/fragments. Receipt carries no query, credentials, raw resource path, hostname, or user ID.

Caller supplies only events and trusted receipts for ONE authenticated Agent/source scope per call. HTTP headers, IP, and User-Agent alone never establish trust. Receipt authenticity/ownership checks happen before this package; document this trust boundary. No IO/network/filesystem/crypto keys in this pure package.

Match a unique request nonce and require exact method, status, path hash, valid timestamps. Never trust a receipt with a mismatched method/path/status or unknown operation/outcome. Conflicting receipts for a nonce invalidate that nonce. Exact duplicate receipts may deduplicate. Multiple raw events sharing a nonce invalidate it; replay cannot authorize two requests. Inputs must remain unchanged. No nondeterministic order/map-based match selection.

Allowed outcomes only:

| operation | method/status/outcome | resulting kind |
|---|---|---|
| ensure_collection | MKCOL405 expected | expected |
| path_exists | PROPFIND404 expected | expected |
| fetch_file | GET or HEAD404 error | integration_error |
| preview_file | GET404 error | integration_error |
| any of these four operations | appropriate operation method + 2xx success | success |

401/403 never classify expected or integration_error. All other 4xx remain threat. For success methods: ensure_collection MKCOL; path_exists PROPFIND; fetch_file GET/HEAD; preview_file GET. ResourceHash=matching PathHash for attributed results, Operation=matching operation. Reasons are generic stable codes; never echo raw request paths into Reason.

## Workflow and permissions

Create code branch `dots/http-outcome-classifier-P-20261030-001`, push only `httpclassification/*.go`, and create a Draft PR against `main`. Do not push directly to main/develop, force push, merge, publish a release, deploy, change access or credentials, install dependencies, or touch customer/private data. No added dependencies. Run `go test ./httpclassification`, format Go, and supply exact commands/exit codes. If toolchain unavailable, report that and let CI/local integrator execute it; do not invent test success.

Have a different reviewer inspect the entire package/tests and adversarial inputs, fix scoped findings, and return code SHA and review evidence. If a premise differs from actual sources, report it rather than implementing blindly. Never edit instruction files or PROGRESS.md.

Non-code implementation/review/test results go to Drive `bot/blob/2026/10/P-20261030-001/v1/`, including all subfolders; write files, re-read/hash every file, then manifest.json last (paths, bytes, SHA256). Revised submissions use v2+. Code remains in Draft PR. No auth URLs. This permission does not include other Drive folders or file overwrite/deletion.

If GitHub save is cancelled, inspect remote state before retrying up to2 times; no force overwrite. After repeated cancellations return base SHA+format-patch/bundle in a fresh Drive version. If explicitly denied by review, stop that action; do not route around it. Drive cancelled saves: inspect same-name/bytes first; retry up to2 times if absent; conflicting content/third cancellation/rejection stops. Return what succeeded and what remains.

First reply must identify task ID, source/instruction commit, repo/branch/PR duplication, toolchain capability, and independent reviewer. Every reply begins `#P-20261030-001 heartdesk:` and stays in the same Slack thread. Record progress on management Issue if supported; if Issue comments unavailable, return it in the same thread and the local parent will copy it with attribution. Do not ask the user to relay.
