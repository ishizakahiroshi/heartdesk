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

**Pre-release. Source only, no prebuilt binaries. Use at your own risk.**

- This code was split out of an internal server-monitoring tool that is still in use. The split is not finished.
- Features specific to one deployment (customer-facing integrations) are not included. The public `app` package provides extension points for applications that own those integrations; see [Embedding the application](#embedding-the-application).
- The old internal names have been replaced by heartdesk names: environment variables are `HEARTDESK_*`, the root is `HEARTDESK_BASE_DIR` (for example `/var/lib/heartdesk`), with `config/`, `data/`, `log/` and `bin/` under it, and the commands are `heartdesk-doctor` and `heartdesk-scheduler`. Old names are not supported.
- Many comments are in Japanese.
- **What has been checked.** On 2026-10-21 the server and the scheduler were run on Windows and on Linux (Ubuntu in WSL) with a synthetic setup, never against real servers: start-up, login, account lockout, the main screens in dark and light themes, receiving signed reports from an agent, alert mail through a local test SMTP server, GeoIP lookups with a synthetic database (and with a missing or broken one), the Nextcloud login button for nine tenant configurations, and the refusal of host-changing operations for remote agents. The commands that host-changing operations would run were checked with fake executables, not on a real host. `go build`, `go vet` and `go test ./...` pass on Windows and Ubuntu in CI; the main packages' tests were also run on Linux.
- **Not checked yet:** host-changing operations on a real host (apt, systemd, fail2ban), the Nextcloud login against a real Nextcloud (the OCS call), lookups with a real GeoIP database or the IPinfo API, mail through a real mail server, and the reverse-proxy rules. Do not rely on any behavior not listed here as verified.
- Known limitations are listed in [Known limitations](#known-limitations).

## Known limitations

These limitations also apply to the embedding API.

- **Sessions are kept in memory.** Restarting the server signs everyone out.
- **Alerts evaluate the machine heartdesk itself runs on.** The scheduler's `alerts` job reads `data/csv/resource_log.csv`, which `collect_resources` writes on that machine, so memory and disk rules are not evaluated per monitored agent. The alert mail has a fixed Japanese one-line body and no server name. The "recovery value" field of a rule is not used. Several settings in `config.toml` (`[scheduler] alert_rules_path` / `alert_state_path`, and most `[alerts]` keys except `rules_file` and `state_file`) are not read by the alerting code.
- **Alert mail** is sent over SMTP with STARTTLS on port 587 or 25 and requires a user name and password; a server without STARTTLS is refused. SMTP settings live in `data/json/alert_rules.json` and are not editable in the UI. That file holds the SMTP password in plain text and is written with mode 0600, so the scheduler must run as the same user as the server.
- **Saving alert recipients in the UI** does not keep the per-recipient "rules" selection (everyone receives every rule again).
- **`cmd/alerts`** is an older copy of the alert logic that keeps its state in a fixed temporary path. Use the scheduler's `alerts` job.
- **GeoIP** is configured with `[paths].geoip_db` (an absolute path to a MaxMind-format database, also for the optional update job) and, for lookups through the API, the IPinfo token. Without them no country is shown. With an IPinfo API that answers slowly, every lookup of the same address waits up to 3 seconds.
- **Host-changing operations** (Monitor action buttons) run only on the machine heartdesk runs on (the agent configured with `is_primary = true`); remote agents are refused. `apt_update` and the `apt_upgrade` family report "started" even if the command later fails; read `data/json/apt_update_state.json` and `data/log/apt_update_*.log`. `fail2ban_ban` does not refuse your own or a loopback address, and "unban" works only for the four built-in jails. These operations use `sudo -n` and need a matching sudoers entry.
- **Login failures** are logged with the length and character kinds of the typed password (not the password itself).
- The server expects a single instance; there is no shared session or lockout store between instances.

## Check that it compiles

```sh
go vet ./...
go build ./...
```

`go build ./...` does not write a binary when several packages are built. To build the server, run `go build .` in the repository root (this writes an executable).

Tests: `go test ./...` (not all packages have tests).

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

- `HEARTDESK_CONFIG_DIR`: directory with `config.toml` and `secrets.toml`. If unset, `$HEARTDESK_BASE_DIR/config` is used (or `/var/lib/heartdesk/config` when `HEARTDESK_BASE_DIR` is not set either).
- `HEARTDESK_BASE_DIR`: base directory for data and for `config/users.toml`. **Required** for the server: the process exits if it is unset. Everything heartdesk itself writes goes under it: `data/` (for example `data/vendor/`, `data/json/`, `data/audit/`, `data/nc_extract/`, `data/avatars/`), `data/logs/` (the scheduler's job logs, such as `collect_resources.log`), `log/` (the login event log) and `bin/`. The scheduler and the other commands use the same root; only code paths that run without `HEARTDESK_BASE_DIR` fall back to `/var/lib/heartdesk`. Places on the monitored host (Nextcloud under `/var/www/nextcloud`, `/var/log/nginx`, `/var/log/fail2ban.log*`, `/var/backups/mariadb`, `/etc/...`) and lock files in `/var/lock` are not moved.
- `HEARTDESK_TENANT_ID`: optional. Unset means the tenant `default`, which this minimal setup uses.
- `HEARTDESK_LOGIN_LOG_PATH`: optional. By default the login event log goes to `$HEARTDESK_BASE_DIR/log/heartdesk_login_events.jsonl`. If that directory does not exist, a line is logged at each login and login still works; create it (`mkdir -p "$HEARTDESK_BASE_DIR/log"`) or set this variable to a writable file path to avoid it.

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
- `password_hash` is the string `bcrypt$` followed by a bcrypt hash, so a stored value looks like `bcrypt$$2a$12$...`. A bare `$2a$...` hash without the `bcrypt$` prefix is refused. The repository has no command that makes this hash, so use a small program outside the repository. In an empty scratch directory, save this as `main.go`, run `go mod init hashgen && go get golang.org/x/crypto@v0.51.0 && go mod tidy` (the pin keeps it on the same `x/crypto` version as heartdesk; the latest one needs a newer Go), then `go run . '<your password>'`:

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

The login page shows the "Nextcloud" login button only when `HEARTDESK_TENANT_ID` names a tenant in `tenants.toml` that has a public host (the button also needs a reverse-proxy rule that passes `/nextcloud/heartdesk-login` to `<login path>/nc`). In this minimal setup the button is not shown.

Cards for a monitored agent show what that agent reported. With only the basic report from the 2026-10-21 check, cards such as system updates, services, disk and SSL show as unavailable until the agent sends the matching data.

## Doctor

`heartdesk-doctor` checks that the templates, the JavaScript files and the configuration agree with each other. It reads `web/templates` and `web/static` from the **current directory**, so run it from the root of this repository:

```sh
HEARTDESK_CONFIG_DIR=/path/to/config go run ./cmd/heartdesk-doctor
```

It is a development check of the source tree, not a diagnosis of a running server. `heartdesk-doctor env` checks the environment variables: only `HEARTDESK_BASE_DIR` is required, and it reports which config directory and tenant would be used when `HEARTDESK_CONFIG_DIR` or `HEARTDESK_TENANT_ID` is unset.

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
```

## Configuration

Settings are read from TOML files in the directory given by `HEARTDESK_CONFIG_DIR`, plus a few environment variables. `app.env.example` lists sample environment variables; see the note at the top of that file about which ones the current code reads. The tenant is chosen with `HEARTDESK_TENANT_ID` (default tenant ID: `default`). For a minimal working setup, see "Build" and "Run (minimal setup)" above.

## Embedding the application

The standalone manual alert evaluator is also available as the public `alertscli`
package. `alertscli.New(Options).Run(testMail)` performs one historical CLI cycle;
`Options.Paths` lets an embedding application supply all seven input/output paths
independently, while `TestSubject` and `TestBody` customize test-mail identity.
Omitted options retain standalone defaults. `Options.Dependencies` replaces clock,
file, command and mail effects per runner for synthetic verification. `Run(true)`
still performs normal evaluation before the execution stamp, test mail and state
save. This compatibility runner retains the manual CLI's legacy state and
best-effort behavior; it does not use the scheduler's alert evaluation semantics.

The public `github.com/ishizakahiroshi/heartdesk/app` package assembles the same
Monitor, authentication, report receiver and scheduler used by the standard CLIs.
Pass an absolute `Options.BaseDir`, explicit `ConfigDir` / `DataDir` when needed,
and either `Config`, `ConfigLoader`, or configuration files loaded with
`app.LoadConfig(configDir, tenantID)`. `ConfigLoader` serves the shared tenant
configuration cache as well as startup. A supplied `Config` and `Environment` map
are copied; hook implementations and returned configuration must remain immutable.

An embedding application may set `Config.NCFileAccessDefaultServiceAccounts` to
define its own fallback for file-access alert classification. Supply it on both
the startup configuration and each `ConfigLoader` result. It is an in-memory
embedding field, not a TOML option. The optional `service_accounts` JSON setting
takes priority when present: `[]` disables service classification and a custom
list replaces the fallback. Missing or null uses the configuration's fallback;
standalone heartdesk assumes no service accounts.

`MonitorIdentity.LegacyStorageNamespace` optionally imports collapsed-card,
server-tree and sidenav-order preferences from a previous namespace before
rendering. The current namespace takes precedence whenever its key exists;
unknown or malformed old values are ignored and old keys are retained. The
default is empty, which disables migration.

```go
runtime, err := app.New(app.Options{BaseDir: root, Config: cfg})
if err != nil {
    return err
}
defer runtime.Close()
return runtime.Run(ctx)
```

`New` validates and assembles the application. It does not listen, open application
databases, run jobs, send notifications, or run privileged startup maintenance.
`Prepare(ctx)` opens durable stores and restores report state and token revocations.
`Handler()` returns HTTP 503 until preparation succeeds, including on `/healthz`.
For an HTTP server owned by the caller, call `Prepare(ctx)` before serving
`Handler()`. `Run(ctx)` calls `Prepare`, runs the normal startup maintenance, and
serves HTTP. `RunScheduler(ctx)` calls `Prepare` and starts the configured jobs;
`SchedulerOnly` supports a separate scheduler process. `Close` cancels work, waits
for active requests and jobs, and closes databases owned by the runtime. Request
handlers and jobs must honor context cancellation.

The current stores and registries permit **one runtime per process lifetime**.
After initialization has begun, another `New` fails with `ErrRuntimeInitialized`,
including after failure or `Close`. A runtime may start the Monitor and scheduler
once each. Preparation is idempotent; a failed preparation remains failed.
SIGHUP / `app.ReloadConfigCache()` clears tenant configuration cache entries.
Routing, environment snapshots, cookies, templates, extensions and startup config
remain fixed until process restart.

`Options.Extensions` registers additional cards, GET/HEAD APIs, POST actions and
GET exports. Hooks receive a `RequestContext` with the shared configuration,
routing, session, agent identity and template renderer. Screen, card, component,
capability, tenant and agent checks remain in the shared dispatcher. `AllActions`
adds required permissions, and `AnyActions` requires at least one listed permission.
`Endpoint.ReadOnly` classifies an added action before session creation; it does
not skip those permission checks or CSRF. `Endpoint.AliasFor` adds an action name
for an existing standard action and checks both names' permissions.

Additional `TemplateFS` and `StaticFS` assets cannot replace standard files or
template definitions. Card IDs, API/action/export names, jobs and overlapping
routes fail initialization on collision. `Routes` require shared screen
authentication or an explicit independent authenticator; `Methods` can restrict
them further. `Jobs`, `Notifiers`, and `OnReportSaved` attach application behavior
without copying the standard runner. Report hooks run after authentication and
successful durable persistence.

`app.ValidateCardConfiguration` checks extension definitions, configured card IDs
and legacy aliases without initializing a runtime. Customer diagnostics can use
this function without maintaining a second copy of the standard card registry.

Customer handlers can reuse `app.RequireScreen`, `WriteActionError`,
`SetDownloadHeader`, `CSVSafe`, `CSVBOM` and `ParseIntParam`. Screen authorization
uses the same session, method and CSRF checks as the standard middleware.
`app.JST`, `FormatDatetime` and `ParseTimestamp` preserve the standard presentation
formats. The public `httpx` package shares the internal client's TLS transports,
body limits, headers and context cancellation behavior.

`Card.ClientOnly` keeps the initial card shell and evaluates its `Data` callback
only through the authenticated card-refresh endpoint.

`DefaultTenantID`, `SelfServiceName`, `ExtractJobID`, routing, branding and cookie
options preserve an embedding application's existing identities. `LicenseConfig`
passes signing material in memory and fixes it before request handlers start.
Its `Issuer`, `Audience`, `OfflineAudience`, `OfflineType` and
`OfflineFilenameExtension` retain the standalone defaults when empty; explicit
values preserve an application's existing tokens and offline download names.
`ActionPermissionAliases` maps shared action names to existing policy keys so
explicit grants and denials survive renamed actions across policy layers.
Omitting `VerifyLicense` keeps the standard license verifier; a nil callback does
not disable verification. Authentication helpers such as `DefaultSessionManager`,
`DefaultStore`, `SessionFromRequest`, `ActionAllowed` and `CanUseCard` expose the
same stores used by the runtime. See `app/testdata/external` for an external-module
compilation fixture with no imports from `heartdesk/internal`.

Report observers receive private copies of configuration and collector payloads;
editing them cannot alter the receiver's caches. User-store path selection honors
explicit options, then existing process environment, then the standard default.

`AuthIdentity` preserves an application's existing login presentation, Nextcloud
entry path, challenge cookie, TOTP issuer and unregistered-account message.
`OperationalIdentity` preserves lock names, script metadata and the trusted audit
principal. `MonitorIdentity` controls display names, browser preference keys and
login-history wire/export names; `VendorName` sets the license attribution.
These optional configurations are validated and copied at startup, and empty
fields keep the standalone defaults. Nextcloud entries must be root-relative paths.

`CardAliases` maps former card IDs to registered current cards when reading
existing policy and preference files. It does not migrate those files on read.
Policy precedence across role, tenant, agent and user layers remains unchanged;
colliding old/current keys in one layer use the more restrictive card mode.
API and export endpoints may also use `AliasFor` to expose a former name for a
same-kind built-in target. Both the alias and its target must authorize the request.
Nextcloud extraction writes to the configured event and access-event directories,
so producers and score readers can continue sharing an existing data location.

## Dependencies

- Go 1.25.13 or later (see `go.mod`; an older `go` command downloads that toolchain by itself unless `GOTOOLCHAIN=local` is set)
- The agent-side signing package from heartpost (`github.com/ishizakahiroshi/heartpost`)
- SQLite through `modernc.org/sqlite` (no cgo)
