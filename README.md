# heartdesk

heartdesk is a dashboard server written in Go for watching several servers from one place. It provides:

- a Monitor web UI with per-server cards (resources, services, logs, SSL, fail2ban, backups, and more)
- a scheduler that collects metrics and runs periodic jobs
- authentication (password, TOTP 2FA, lockout, CSRF, trusted-proxy handling) and role-based access to screens and actions
- alerting (email, plus a small registration hook for additional notifiers)
- tenant management and a Vendor Console for managing tenants, agents and licenses

It receives heartbeat reports over HTTP from the agent side. The agent side is the sibling project [heartpost](https://github.com/ishizakahiroshi/heartpost), which sends signed reports from the monitored servers.

License: Apache-2.0 (see `LICENSE`).

## Status

**Work in progress. Not released yet.**

- This code was split out of an internal server-monitoring tool that is still in use. The split is not finished.
- Features that were specific to one deployment (customer-facing integrations) are not included. Where such a feature used to plug in, there may be no replacement yet.
- Renaming to the heartdesk brand is not finished. Old names remain in environment variables (`SAB_*`, `NAB_*`), default paths (for example `/home/sab/...`), card IDs, cookie names, `localStorage` keys, favicon file names, the `sab-doctor` and `sab-scheduler` command names, and in log messages. <!-- secrets-scan: allow -->
- Many comments are in Japanese.
- **The server has not been started or tried end to end.** Only compilation, `go vet` and part of the unit tests have been checked. The web UI has not been viewed in a browser. Do not rely on any behavior described here as verified.

## Check that it compiles

```sh
go vet ./...
go build ./...
```

`go build ./...` does not write a binary when several packages are built. To build the server, run `go build .` in the repository root (this writes an executable).

Tests: `go test ./...` (not all packages have tests; the full result has not been recorded yet).

## Layout

```
main.go              entry point: loads config, wires routes, starts the HTTP server
app.env.example      sample environment variables
internal/            shared packages: config, routing, auth, authz, alerts, scheduler,
                     vendorsvc (SQLite stores), license, navmeta (card registry), and others
core/monitor/        the Monitor: HTTP handlers, card APIs, agent report receiver
core/vendor_console/ Vendor Console exports and license-key rotation
cmd/                 command-line tools: alerts, sab-doctor, sab-scheduler
web/                 HTML templates and static files (CSS, JS), embedded into the binary
docs/                documents (docs/local is not tracked by git)
```

## Configuration

Settings are read from TOML files in the directory given by `SAB_CONFIG_DIR`, plus a few environment variables. `app.env.example` lists sample environment variables; see the note at the top of that file about which ones the current code reads. The tenant is chosen with `SAB_TENANT_ID` (default tenant ID: `default`).

## Dependencies

- Go 1.25 or later (see `go.mod`)
- The agent-side signing package from heartpost (`github.com/ishizakahiroshi/heartpost`)
- SQLite through `modernc.org/sqlite` (no cgo)
