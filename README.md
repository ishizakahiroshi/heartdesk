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
- The old internal names have been replaced by heartdesk names: environment variables are `HEARTDESK_*`, the default root is `/var/lib/heartdesk`, with `config/`, `data/`, `log/` and `bin/` under it (the same layout as `HEARTDESK_BASE_DIR`), and the commands are `heartdesk-doctor` and `heartdesk-scheduler`. Old names are not supported.
- Many comments are in Japanese.
- **Only a small part has been tried end to end.** On 2026-10-21 the server was started on Windows with a synthetic setup (no real servers). Login, the main screens, and receiving a signed synthetic report from an agent were checked in a browser. **Not checked yet:** normal operation on Linux, write operations (anything that changes a monitored server), Nextcloud login, notifications, and the scheduler. Do not rely on any behavior not listed here as verified.

## Check that it compiles

```sh
go vet ./...
go build ./...
```

`go build ./...` does not write a binary when several packages are built. To build the server, run `go build .` in the repository root (this writes an executable).

Tests: `go test ./...` (not all packages have tests; the full result has not been recorded yet).

## Build

The server will not start unless a secret named `vendorSecret` is injected at build time. It is the key used to sign and check license keys (HMAC-SHA256 over `<tenant_id>.<agent_id>`). The source deliberately has no default, because anyone who knows the value can create valid license keys.

You choose the value yourself. It must be the same value you use to compute every license key that this build has to accept: the Monitor's own key in `secrets.toml` (see "Run") and the license keys of agents that call `/api/license/verify`. A key computed with a different value is rejected. The value is embedded in the binary, so treat the binary as secret too.

```sh
VENDOR_SECRET="$(openssl rand -hex 32)"   # keep it: you need it again to compute license keys
go build -ldflags "-X github.com/ishizakahiroshi/heartdesk/internal/license.vendorSecret=${VENDOR_SECRET}" -o heartdesk .
```

Without the flag the server stops at start-up with `license verification failed: license: vendorSecret not injected at build time; rebuild with -ldflags ...`. Use the full module path in `-X`. These commands use POSIX shell syntax. On Windows, run them in Git Bash (which ships `openssl`); PowerShell has no `openssl` by default. Output from `openssl` in Git Bash can end with a carriage return: when you redirect it to a file, strip the `\r` (for example `| tr -d '\r'`), or a key will be one byte too long.

## Run (minimal setup)

This is based on the setup used for the 2026-10-21 start-up check; sections that were left empty there are omitted. Samples are in `examples/config/`.

**1. Environment variables**

- `HEARTDESK_CONFIG_DIR`: directory with `config.toml` and `secrets.toml`. If unset, the code falls back to `/var/lib/heartdesk/config`; set it explicitly for a setup outside a system install.
- `HEARTDESK_BASE_DIR`: base directory for data and for `config/users.toml`. **Required**: the process exits if it is unset. heartdesk writes under `$HEARTDESK_BASE_DIR/data/` (observed: `data/vendor/`, `data/json/agent_reports/`, `data/audit/`).
- `HEARTDESK_TENANT_ID`: optional. Unset means the tenant `default`, which this minimal setup uses.
- `HEARTDESK_LOGIN_LOG_PATH`: optional. By default the login event log goes to `/var/lib/heartdesk/log/heartdesk_login_events.jsonl`. If that directory does not exist, a line is logged at each login and login still works; set this variable to a writable file path to avoid it.

**2. `config.toml`** (in `HEARTDESK_CONFIG_DIR`; sample: `examples/config/config.toml.example`)

- `[server] listen_addr`: listen address. If empty, `:8765` (all interfaces) is used. Prefer loopback behind a reverse proxy.
- `[agent."<agent_id>"]` with `agent_id`, `agent_type` (`vps` or `rental`), `agent_label`: one table per monitored server.
- `[agent."<agent_id>"] is_primary`: optional, default `false`. Set `true` only for the server that heartdesk itself runs on. For that agent, cards and actions run commands on this machine. For every other agent (including `default_agent`), cards are built only from the reports the agent sends, and a card whose data the agent does not send shows as unavailable.
- `[ui] default_agent`: the agent shown first. It does not make that agent local; see `is_primary`.
- `[agent_report] strict_license`: the default is `true`, which rejects a report that has no Bearer (JWT) token. The minimal setup sets `false` so that reports with only the HMAC signature are accepted.

An `agent_id` must look like `<tenant_id>-<name>` (for the default tenant: `default-web-01`). The part before the first `-` is the tenant ID and may contain only `a-z`, `0-9` and `_`. Entries in `[agent_keys]` and `[agent_allowed_ips]` whose tenant matches but which have no `[agent."<id>"]` table are dropped at load time with a log message.

**3. `secrets.toml`** (in `HEARTDESK_CONFIG_DIR`; keep it out of git; sample: `examples/config/secrets.toml.example`)

- `[vendor_license] tenant_id` and `license_key`: checked at every start-up. The key has the form `<tenant_id>.<tenant_id>-monitor.<signature>`, where `<signature>` is the lowercase hex HMAC-SHA256 of the string `<tenant_id>.<tenant_id>-monitor` with `vendorSecret` as the key. For the default tenant:

  ```sh
  printf '%s' "default.default-monitor" | openssl dgst -sha256 -hmac "$VENDOR_SECRET" | sed 's/^.*= //'
  ```

  Put `default.default-monitor.` followed by the printed hex into `license_key`.
- `[agent_keys]`: `"<agent_id>" = "<shared key>"`. The key used to sign that agent's reports. An agent with no entry is rejected.
- `[agent_allowed_ips]`: `"<agent_id>" = ["<ip or CIDR>", ...]`. An agent with no entry, or an empty list, is rejected with HTTP 403. The address checked is the one heartdesk sees (a forwarded address is used only when the request comes through a configured trusted proxy).

**4. `users.toml`** (default: `$HEARTDESK_BASE_DIR/config/users.toml`; `HEARTDESK_USERS_TOML` overrides the path; sample: `examples/config/users.toml.example`)

Each `[[users]]` entry has `id`, `username`, `name`, `password_hash`, `role` and `access_screens`.

- `role` is one of `vendor_staff`, `tenant_admin`, `tenant_user`.
- `access_screens` is a list of `monitor` and/or `vendor`. If it is omitted or empty, the user cannot open any screen.
- `password_hash` is the string `bcrypt$` followed by a bcrypt hash, so a stored value looks like `bcrypt$$2a$12$...`. A bare `$2a$...` hash without the `bcrypt$` prefix is refused. The repository has no command that makes this hash, so use a small program outside the repository. In an empty scratch directory, save this as `main.go`, run `go mod init hashgen && go mod tidy`, then `go run . '<your password>'`:

  ```go
  package main

  import (
  	"fmt"
  	"os"

  	"golang.org/x/crypto/bcrypt"
  )

  func main() {
  	h, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), 12)
  	if err != nil {
  		panic(err)
  	}
  	fmt.Println("bcrypt$" + string(h))
  }
  ```

  This prints one line to paste into `password_hash`. The password ends up in your shell history; clear it or type it another way if that matters.

**5. Start**

```sh
export HEARTDESK_CONFIG_DIR=/path/to/config
export HEARTDESK_BASE_DIR=/path/to/base
./heartdesk
```

Open `http://<listen_addr>/login` in a browser. After login, the Monitor is at `/monitor/`. (These are the default paths, used when `HEARTDESK_ROUTING_MODE` is unset.)

**6. Agent reports**

`POST /api/agent/report` is authenticated by the signature, not by a login session. The sender sets these headers: `X-Agent-Id`, `X-Agent-Timestamp` (Unix seconds; by default it must be within 120 seconds of the server clock, see `[agent_report] timestamp_skew_sec`) and `X-Agent-Signature` (lowercase hex HMAC-SHA256 of `<timestamp>.<raw body>`, keyed with that agent's `[agent_keys]` value). The JSON body must contain the same `agent_id`. The agent-side sender is [heartpost](https://github.com/ishizakahiroshi/heartpost).

Not part of this minimal setup and not described here: `tenants/<id>/` overrides, the `[security]`, `[alerts]`, `[geoip]` and `[nextcloud]` sections, TOTP, and the scheduler.

One thing you may notice with this minimal setup:

- The login page shows a "Nextcloud" login button even when Nextcloud is not configured. It leads to a 404.

Cards for a monitored agent show what that agent reported. With only the basic report from the 2026-10-21 check, cards such as system updates, services, disk and SSL show as unavailable until the agent sends the matching data.

## Doctor

`heartdesk-doctor` checks that the templates, the JavaScript files and the configuration agree with each other. It reads `web/templates` and `web/static` from the **current directory**, so run it from the root of this repository:

```sh
HEARTDESK_CONFIG_DIR=/path/to/config go run ./cmd/heartdesk-doctor
```

It is a development check of the source tree, not a diagnosis of a running server. The `env` sub-command currently fails when `HEARTDESK_TENANT_ID` is unset, although the tenant ID is optional for the server itself.

## Health check

`GET /healthz` (also `HEAD`) needs no login and returns HTTP 200 with the body `{"status":"ok"}`. It returns no version, host name or configuration. Use it for uptime monitors, load balancers and container health checks.

```sh
curl -i http://127.0.0.1:8765/healthz
```

Other methods get HTTP 405.

## Layout

```
main.go              entry point: loads config, wires routes, starts the HTTP server
app.env.example      sample environment variables
examples/config/     minimal sample config.toml, secrets.toml and users.toml
internal/            shared packages: config, routing, auth, authz, alerts, scheduler,
                     vendorsvc (SQLite stores), license, navmeta (card registry), and others
core/monitor/        the Monitor: HTTP handlers, card APIs, agent report receiver
core/vendor_console/ Vendor Console exports and license-key rotation
cmd/                 command-line tools: alerts, heartdesk-doctor, heartdesk-scheduler
web/                 HTML templates and static files (CSS, JS), embedded into the binary
docs/                documents (docs/local is not tracked by git)
```

## Configuration

Settings are read from TOML files in the directory given by `HEARTDESK_CONFIG_DIR`, plus a few environment variables. `app.env.example` lists sample environment variables; see the note at the top of that file about which ones the current code reads. The tenant is chosen with `HEARTDESK_TENANT_ID` (default tenant ID: `default`). For a minimal working setup, see "Build" and "Run (minimal setup)" above.

## Dependencies

- Go 1.25 or later (see `go.mod`)
- The agent-side signing package from heartpost (`github.com/ishizakahiroshi/heartpost`)
- SQLite through `modernc.org/sqlite` (no cgo)
