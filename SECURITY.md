# Security policy

heartdesk is pre-release software (see the Status section of `README.md`). There are no supported
versions yet; fixes go to the `main` branch.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- Use GitHub's private vulnerability reporting: the **Report a vulnerability** button on the
  repository's **Security** tab.
- If that is not available, email ishizakahiroshi.dev@gmail.com with "heartdesk security" in the subject.

Include what you found, the version or commit, and steps to reproduce. This is a one-person project:
expect a reply when I can, not a fixed response time.

## Areas that matter most

heartdesk handles credentials and signed requests, so reports about these are especially welcome:

- login, sessions, CSRF, two-factor authentication and account lockout (`internal/auth`)
- role-based access to screens, cards and actions (`internal/authz`, `core/monitor`)
- verification of agent reports and licenses (`internal/license`, the signature check on `/api/agent/report`)
- anything that lets a request run a command, or read or write a file, outside what the feature is meant to touch

## Keeping a deployment safe

- The build-time `vendorSecret` signs and checks license keys. Anyone who knows it can create valid
  license keys. It is embedded in the binary you build, so keep that binary private.
- Keep `secrets.toml` and `users.toml` out of git and readable only by the service user.
- Put heartdesk behind a reverse proxy with TLS; the default listen address in the sample config is loopback.
