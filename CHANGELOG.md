# Changelog

## [1.2.0] - 2026-10-10

Changes since the v1.1.1 tag.

### Added

- Customers can sign up on the website, receive an integration key once, and return to their own dashboard using email and password.
- Existing API-only tenants can enable dashboard access by proving ownership of their current key. Owners can replace a lost key after confirming their password.
- Tenant dashboards show actual authorization activity, behavioral risk, audit events, threat signals, analytics and quota usage.
- PostgreSQL-backed multi-tenant storage, Redis caching, per-tenant quotas, Prometheus metrics, Grafana provisioning, audit proofs and compliance report templates.
- Email, Slack and webhook alert channels; IP reputation, geo-velocity, behavioral baselines and TLS fingerprint signals.
- Analytics and ROI endpoints; Node.js and Go SDKs, Datadog/Splunk integration modules and Terraform onboarding.

### Changed

- Browser access uses expiring, revocable HttpOnly sessions. Integration keys stay on customer servers and are stored as hashes.
- Customer dashboard reads and actions use the authenticated tenant. Demo simulation and reset controls are restricted to the demo tenant.
- Root and canonical frontend entry points share one dashboard and an API proxy. Production settings, credentials and service ports use environment configuration.
- Audit views include decision-time risk scores, strike state, block duration and detector contributions.

### Fixed

- Signup and login request hangs, timeout handling, frontend/backend connection failures and blocking database work in async middleware.
- Cross-tenant access gaps, inconsistent risk thresholds, strike transitions, reset state and score bounds.
- Database migrations on existing deployments and risk-score propagation through audit readers and proof hashes.
- SMTP configuration, quota accounting, metrics, deployment configuration, SDK dependencies and Terraform provisioning.

### Verification and limits

- 135 backend tests pass on SQLite and disposable PostgreSQL 16; 11 frontend tests, lint and builds pass. Live browser/API checks cover account access and real authorization activity.
- Account email verification, password recovery, MFA, invitations and overlapping-key rotation remain future work.
- HTTPS and a same-site API/proxy are required for production browser sessions. External alert delivery, container deployment and production capacity have not been verified by local tests.
- SDK packages retain their independent package versions; v1.2.0 identifies the CyberAccess platform release.

[1.2.0]: https://github.com/BUILD-WITH-BARATH/Build_with_Barath_2.0/compare/v1.1.1...v1.2.0
