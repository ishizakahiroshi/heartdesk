# Independent review

Review the entire changed package and tests. Verify all allowed combinations and all near misses, lowercase identifier validation, query stripping/exact escaped path hashing, invalid escapes, absolute URLs/fragments, cutoff/future/skew boundaries, stale/future receipt paired with valid event, duplicate/conflicting receipt, nonce reuse by two raw events, input immutability and deterministic result order, unknown operation/outcome,401/403, spoofed header with no receipt, old logs lacking new fields,2xx recovery evidence.

Use synthetic203.0.113.x/example.com data only. No private logs/hosts/users. Include a negative control proving a valid receipt fails when one binding field changes. No WSL, no live network probe, no new dependencies, no changes outside httpclassification Go files. Do not claim independent review from the implementer.
