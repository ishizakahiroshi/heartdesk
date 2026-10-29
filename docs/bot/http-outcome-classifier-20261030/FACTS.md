# Facts

The existing scheduler scores generic Nextcloud HTTP4xx without caller intent (`internal/scheduler/daemon/score.go`, collectNC4xxEventCounts, baseline990ea7a). This task adds pure trusted-outcome correlation only; it does not change that runtime yet.

The local producer creates a fresh random128bit request nonce for each explicitly marked outbound operation, sends it in X-HTTP-Operation-ID, and records a local outcome receipt. A configured collector authenticates the receipt stream through the existing Agent reporting signature. Nginx separately records request_id. Raw access and receipt may arrive in either order; consumer correlates each scoring run, so late receipts can classify later. Old access logs without receipts remain unknown/threat.

These are generic protocol requirements, not proof that any production deployment already has those fields. No production data or customer names are part of this task.
