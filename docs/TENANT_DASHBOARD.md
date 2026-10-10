# Tenant dashboard access

## Research and design (10 October 2026)

The website must give customers a repeatable way to see their security data after their one-time API key is issued. Issuing a key alone is not account onboarding.

| Primary source | Observed pattern | Application here |
| --- | --- | --- |
| [WorkOS users and organizations](https://workos.com/docs/authkit/users-organizations) | Users belong to organizations; permissions depend on organization membership. | A dashboard owner belongs to exactly one tenant. Every dashboard read and action uses that authenticated tenant. |
| [WorkOS sessions](https://workos.com/docs/authkit/sessions) | Browser sessions carry user, organization and role; tokens belong in secure cookies and expire. | HttpOnly, SameSite cookies, secure in production, with server-side session revocation. Integration keys do not authenticate the dashboard. |
| [Snyk API authentication](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api) | Customers register and log in to manage credentials; automation uses service-account credentials. | Account login and server-to-server API authentication are separate flows. |
| [Stripe API keys](https://docs.stripe.com/keys) | Newly created live secret keys are shown once; lost keys need replacement. Secret keys stay on servers. | Keep hash-only storage and one-time display. An authenticated owner can explicitly replace a lost key after entering their password. |
| [WorkOS roles and permissions](https://workos.com/docs/authkit/roles-and-permissions) | Administrative privileges are scoped to an organization. | A customer owner cannot read another tenant or operate the shared demo simulator/reset. |
| [Salt platform](https://salt.security/platform) | Salt describes visibility, behavioral baselines, correlated identity and blocking as parts of its security offering. | Dashboard value comes from a customer's actual authorization telemetry, risk decisions and audit evidence. Vendor marketing is not evidence that our model matches its efficacy. |
| [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) | Object authorization must be checked for every object access. | CyberAccess adds behavioral defense to the application's own ownership checks; it cannot infer those checks from an API key. |

## User flows

1. New customer: `/signup` collects organization, email and password; atomically creates a tenant and owner, starts a session and shows the API key once. Continue to `/dashboard` after saving the key.
2. Returning customer: sign in with email and password. Refreshing or reopening the dashboard restores an unexpired session. Signing out revokes it.
3. Existing API-only customer: `/claim` verifies their current API key and creates the tenant's first dashboard owner. An existing owner cannot be overwritten or claimed again. This does not change the integration key.
4. Dashboard: organization identity, tenant-specific activity, risk, threat summary, quotas and integration instructions. No customer demo controls. Zero activity is explained as waiting for integration, not silently filled with demo data.
5. Lost integration key: the owner explicitly confirms replacement with their password. The new key is shown once, and the old key immediately stops working. This is not a grace-period rotation; update the integration immediately.

## Security and compatibility

- Reuse the current `users` password hashing and tenant-aware JWT authorization. Add an email-to-owner mapping and expiring, revocable dashboard session records in migration 20.
- Only normalized, unique account emails select a dashboard owner. Do not claim old tenants by contact email or organization name.
- Session cookies are HttpOnly, SameSite=Lax, Secure by default in production. Cookie-authenticated writes require a custom console header and a permitted Origin. Production CORS must list permitted origins.
- Dashboard sessions do not consume server integration quotas. Existing API-key and legacy demo JWT integrations continue to work.
- Keep the API-only `/v1/signup` contract for existing scripts. Website account signup uses `/auth/signup`. Demo subject login remains available separately.
- No paid authentication provider or new runtime dependency is required.
- Account emails are not verified. Email verification, password recovery, MFA, team invitations, multiple organizations and overlapping-key rotation remain separate work; this change does not claim those capabilities.

## Verification plan

Test signup and rollback, normalized email login, legacy-key claiming and concurrent claims, session restore/logout/revocation, cookie flags and CSRF, tenant isolation for all dashboard readers, quota separation, explicit key replacement, and unchanged demo/API contracts on both SQLite and PostgreSQL. Build and test the frontend, check public pages in a browser, and verify the account-to-dashboard flow with a disposable local account.

## Reused components and scope

Reuse FastAPI, bcrypt, signed tenant identities, the PostgreSQL/SQLite database layer, schema migrations, the existing authorization engine, audit readers, analytics endpoints and React dashboard. The implementation introduces one cookie adapter rather than a parallel authorization service. Implementation is sequential because the frontend contract depends on the identity and session endpoints; database and frontend verification can run independently.

Not in scope: paid authentication providers (the requested stack is free); multiple memberships, invitations and MFA (require a separate account-management flow); email verification and password recovery (require an authenticated email-delivery flow); key grace periods (the current tenant schema has one active integration key); production load testing and deployment (local functional verification cannot establish capacity or availability).

## Data flow and failure handling

```text
Signup / existing-key claim
  -> validate organization/email/password (400 on invalid input)
  -> hash password outside the transaction
  -> transaction: tenant + user + unique owner + session
     -> duplicate email/owner: 409, rollback all writes
     -> database failure: rollback; UI releases pending state
  -> HttpOnly cookie + owner profile (+ one-time key on signup only)
  -> /dashboard -> restore session -> tenant-specific readers

Dashboard request
  -> cookie adapter
     -> unsafe method: console header + allowed Origin (403 if missing/invalid)
     -> verify signed token + live session + current user role (401 if revoked)
  -> current tenant's events / stats / risk / analytics / quota
     -> cross-tenant URL: 403
     -> exhausted integration quota: dashboard remains accessible
     -> no-store response; browser API timeout releases pending requests

Logout -> delete server session + expire cookie -> copied session rejected
Key replacement -> owner password -> compare current key hash + write audit atomically
                -> new key shown once; old key rejected; no key in audit records
```

The request-body inspector and GraphQL resolver reuse the same session validation, so a revoked cookie cannot create audit side effects or retain GraphQL access. In-flight frontend responses are guarded by a session generation so the previous tenant's pending results cannot populate a new login.

## Verification results

- Backend: 135 tests pass on temporary SQLite and disposable PostgreSQL 16, including 24 account/dashboard cases. Operator databases are never used by the tests.
- Frontend: 11 API tests; canonical frontend and root entry-point lint/build checks. Cookie restoration covers guests and returning users.
- Running proxy/backend: account signup, actual allow/deny decisions, two audit events, own-tenant analytics, logout and returning login verified through `http://127.0.0.1:5177/api`. Warm local signup took 37 ms in test mode (bcrypt cost 4); this is not a production latency or capacity claim.
- The active preview uses the previous session's local test database. Upgrading it from schema 19 to 20 preserved all four existing tenants and its audit event. A second proxy/backend smoke test passed after the upgrade (51 ms local signup).
- Browser: API-created disposable tenant rendered the actual authenticated customer dashboard, survived page reload, displayed its own tenant identity and empty activity, and exposed no demo reset/simulator controls. The signup page and dashboard had no console errors; desktop had no horizontal overflow. The key replacement confirmation rendered without replacing that browser fixture's key. Browser QA did not type passwords or inspect cookies/tokens. Form submission contracts and returning login were exercised by automated HTTP/API tests.
- Deployment requires HTTPS and a same-site API/proxy for SameSite=Lax session cookies. Email verification, recovery, MFA and production load testing remain unimplemented; these are explicit limits, not claims of enterprise readiness.

## GSTACK REVIEW REPORT

| Review | Result | Decision |
| --- | --- | --- |
| Architecture | Separate user sessions and integration keys; reuse tenant identity and existing database. | Accepted within the user's requested tenant-dashboard scope. |
| Code quality | Shared identity/profile helpers, migration, existing API helpers and UI components. | Avoid a new auth provider and duplicate dashboard. |
| Tests | Account lifecycle, tenancy boundaries, key ownership, rollback and concurrency need regressions. | Test on both database backends. |
| Performance | Hash passwords outside database transactions; database pool and async middleware must remain responsive. | Verify local signup latency and do not claim production capacity from local timings. |
| Outside voice | Running inside Codex; nested Codex review skipped. | No independent model review is claimed. |

VERDICT: Implement the tenant console and preserve the API-only onboarding contract. Full interactive plan-review prompts were not used because the user requested research followed by implementation and authorized these routine implementation decisions.

NO UNRESOLVED DECISIONS
