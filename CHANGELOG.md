# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - Unreleased

First release, as a pre-release. heartdesk is the dashboard side of a small monitoring pair: it receives
signed reports from [heartpost](https://github.com/ishizakahiroshi/heartpost) agents and shows them in one place.
It was split out of an internal server-monitoring tool; see the Status section of `README.md`.

### Added

- Monitor web UI with per-server cards: resources, services, logs, SSL, fail2ban, backups and more
- Scheduler (`heartdesk-scheduler`) that collects metrics and runs periodic jobs
- Authentication: password login, TOTP two-factor authentication, account lockout, CSRF protection and trusted-proxy handling
- Role-based access to screens, cards and actions
- Alerting by email, with a registration hook for additional notifiers
- Tenant management and a Vendor Console for tenants, agents and licenses
- Receiver for HMAC-signed agent reports (`POST /api/agent/report`)
- `GET /healthz` for uptime monitors
- `heartdesk-doctor`, a check that the templates, the JavaScript files and the configuration agree

### Notes

- Source release only. The server refuses to start unless you inject your own `vendorSecret` at build time
  (see "Build" in `README.md`), so there are no prebuilt binaries.
- Everything heartdesk itself writes lives under `HEARTDESK_BASE_DIR`.
- Checked so far: start-up, login, the main screens and a signed report on Windows and on Ubuntu (WSL) with
  synthetic data, plus the build, vet and tests on Ubuntu and Windows in CI.
- Not checked yet: Nextcloud login, GeoIP, notifications, operations that change a monitored host (apt, systemd,
  fail2ban), and the scheduler against a real Nextcloud.
