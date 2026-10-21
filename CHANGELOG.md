# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-10-21

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
- Checked so far, on Windows and on Ubuntu (WSL) with synthetic data only: start-up, login, account lockout, the
  main screens in the dark and light themes, signed agent reports, alert mail through a local test SMTP server,
  GeoIP lookups with a synthetic database, the Nextcloud login button, and the refusal of host-changing operations
  for remote agents; plus the build, vet and tests on Ubuntu and Windows in CI.
- Found and fixed during that review, before this release: the account lockout never triggered; a mismatch between
  the configured and the reported agent type gave inconsistent screens and alert thresholds; saving alert rules in
  the UI erased the SMTP settings; a failed alert mail was never retried; disabled alert recipients still received
  mail; failed fail2ban / apt operations were reported as successful; the GeoIP database was never reloaded after
  an update.
- Not checked yet: host-changing operations on a real host (apt, systemd, fail2ban), the Nextcloud login against a
  real Nextcloud, lookups with a real GeoIP database or the IPinfo API, and mail through a real mail server.
- Known limitations are listed in `README.md`.
