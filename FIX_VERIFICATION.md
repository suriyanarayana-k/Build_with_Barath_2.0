# Fix verification — 10 October 2026

Status: **DONE_WITH_CONCERNS**. The fixes below pass their regression checks.
Docker deployment and a production load test remain unverified.

## Problems fixed

| Symptom or defect | Cause and change | Main files |
| --- | --- | --- |
| Signup/login could remain pending | Removed private request-body replay code, moved blocking inspection off the event loop, restored POST signup, added a timeout covering response bodies, and routed browser requests through `/api`. | `bola-benchmark/app.py`, `bola-frontend/src/lib/api.ts` |
| Signup generated dashboard traffic | Polling now starts after login and schedules the next refresh after the previous one finishes. | `bola-frontend/src/App.tsx` |
| Different frontends depending on launch directory | Root and standalone launches use the canonical frontend, with React deduplication and the same API proxy. | `vite.config.ts`, `bola-frontend/vite.config.ts`, `src/App.tsx` |
| Admin password bundled in browser code | Removed automatic admin login. Dashboard requests use the current user's token; expired sessions return to login. | `bola-frontend/src/lib/api.ts`, `bola-frontend/src/pages/Login.tsx` |
| Foreign tenant audit/risk/lockout data accessible | Readers use the verified tenant; tenant administrators cannot manage another tenant. Untrusted tenant headers cannot override API-key identity. | `bola-benchmark/app.py` |
| PostgreSQL configuration ignored | Added a PostgreSQL connection pool and retained SQLite for development. Tests use disposable databases. | `bola-benchmark/database.py`, `bola-benchmark/conftest.py` |
| Migration failures hidden or incomplete | Migrations fail explicitly, check existing columns, use transactions, and normalize numeric timestamp fields. PostgreSQL audit queries bind wildcard patterns as parameters. | `bola-benchmark/migrations.py`, `bola-benchmark/app.py` |
| Quotas bypassed without Redis | Added an atomic database fallback and an atomic Redis counter. Partial quota updates preserve existing values and reject invalid limits. | `bola-benchmark/app.py` |
| Risk threshold settings did nothing | Decisions and categories use the tenant's saved thresholds. String values such as `"false"` cannot grant authorization. Invalid batches fail before writing decisions. | `bola-benchmark/app.py` |
| Eight concurrent requests created eight strikes | Strike and ban transitions now use one transaction, plus a shared PostgreSQL advisory lock for each tenant/subject. | `bola-benchmark/app.py` |
| Demo controls affected customer defense | Defense toggling requires a demo admin; customer protection and canary configuration remain scoped to the customer tenant. | `bola-benchmark/app.py` |
| Canary Probe button failed | Replaced its missing endpoint with the existing canary campaign API. | `bola-frontend/src/App.tsx`, `bola-frontend/src/lib/api.ts` |
| Signup keys could not manage analytics | Tenant API keys now access their own quotas, channels, and analytics. | `bola-benchmark/app.py` |
| SMTP delivery broken | TLS, authentication, and delivery use one SMTP connection with a timeout. Email HTML is escaped. | `bola-benchmark/alerting.py` |
| Audit proof overstated integrity/compliance | Snapshot hashes include all selected audit fields. Verification compares an independently supplied root; compliance is marked not assessed. | `bola-benchmark/app.py` |
| Metrics/Grafana panels empty or invalid | Authorization paths update decision, latency, and score metrics. Stored-event counts come from the database. Grafana uses provisionable JSON and histogram bucket queries; authorized-request blocks are not labelled confirmed false positives. | `bola-benchmark/app.py`, `grafana-dashboards/cyberaccess-dashboard.json` |
| Terraform provisioning failed on Windows/new tenants | Uses tenant API keys and sensitive header files, selects PowerShell/curl.exe on Windows, and bounds HTTP timeouts. | `terraform-cyberaccess/main.tf` |
| Container config missed operator settings | Passed through implemented SMTP, quota, threat, and SIEM settings; corrected frontend API routing and dashboard provisioning. Removed leading BOMs from deployment files and unused settings from the example environment. | `docker-compose.yml`, `render.yaml`, `.env.example` |
| Vulnerable JavaScript dependencies | Updated frontend styling/build dependencies and Node SDK test/build tooling, then verified builds and npm audits. | Package manifests and lockfiles |

## Verification evidence

```text
Backend, temporary SQLite:     111 passed, 19 warnings in 29.51s
Backend, PostgreSQL 16:         111 passed, 19 warnings in 35.44s
Python SDK:                     18 passed, 2 warnings
Node SDK:                       10 passed; typecheck and ESM/CJS/declaration builds passed
Go SDK:                         go test ./... and go vet ./... passed
Frontend API regressions:       6 passed
Frontend and root builds:       passed
Frontend and root lint:         passed
npm audit, all 3 Node projects:  0 reported vulnerabilities
Terraform 1.9.8 on Windows:     fmt/validate passed; local tenant, quota, and channel provisioned
Second Terraform plan:          no changes
Deployment YAML:                expected service/configuration keys validated
Git whitespace check:           passed
```

Real browser signup reached **You're all set**, released the pending state, and
reported no console errors. The measured API request took **41 ms** in the first
run and **106 ms** after restarting the backend. A final HTTP check through Vite
created a key in **600 ms**, successfully authorized a request, and confirmed the
authorization decision appeared in Prometheus output. These measurements are
local verification results, not production latency guarantees.

Regression coverage is in `bola-benchmark/test_regressions.py` and
`bola-frontend/tests/api.test.mjs`. CI now includes both database backends and both
frontend entry points; the new workflows have not been run remotely in this task.

## Practical limits

The running preview is `http://127.0.0.1:5177/signup`, with the backend on port
8017 and an isolated temporary SQLite database. Preview keys belong to that
instance. Production/Neon data was not used for the test suite.

Docker/Grafana were checked through configuration and backend metrics, without
launching the full container stack. SMTP delivery was verified with a mock;
real SMTP, Slack, Datadog, Splunk, and external threat feeds were not contacted.
The model remains a prototype with synthetic training. SSE remains local to one
worker. Audit storage/retention settings do not yet implement archival or retention
enforcement, and snapshot hashes do not provide an independently anchored immutable
ledger or compliance certification. Production scaling still needs a load test.

Lost & Found remains the separate test app. Its pre-existing local database
modification was preserved.
