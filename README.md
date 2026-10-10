# CyberAccess

Current release: [v1.2.0](https://github.com/BUILD-WITH-BARATH/Build_with_Barath_2.0/releases/tag/v1.2.0). See the [changelog](CHANGELOG.md) for release details.

CyberAccess adds behavioral BOLA/IDOR detection to object authorization. A customer backend checks whether its user may access an object, sends that decision to `/v1/authorize`, and enforces the returned `allow`, `deny`, or `block` decision before returning data.

The demo API also implements ownership, assignments, delegation, mutation permissions, hierarchy validation, batch access, jobs, GraphQL, stored references, ABAC, and canary records. The React dashboard shows audit events, risk, threat signals, and analytics. Lost & Found is a separate Django test application.

## Run locally

Use Python 3.12+ and Node 22.12+ or 24+. In one terminal:

```powershell
cd bola-benchmark
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_dev_server.py
```

In another terminal, from the repository root:

```powershell
npm ci
npm run dev
```

Open `http://localhost:5173/signup` to create an organization, email/password account and API key. Save the one-time key, then open your dashboard. Return at `/login` with your email and password. Existing API-only tenants can enable dashboard access at `/claim` using their current key. Local demo users have a separate login option; the configured demo admin is `security_admin` with `admin_changeme123`. API docs: `http://127.0.0.1:8000/docs`.

Both the root frontend and `bola-frontend` use the same dashboard. In development, Vite proxies `/api` to `http://127.0.0.1:8000`; set `BACKEND_PROXY_TARGET` in the frontend `.env` to change that target. Dashboard polling starts after login, uses an HttpOnly session cookie, selects the authenticated tenant and waits for each refresh before scheduling another. Signing out revokes the session. Customer owners see their own activity and quota usage; demo simulator/reset controls are limited to demo accounts. Neither API keys nor session tokens are saved in browser storage.

Without `DATABASE_URL`, development uses `bola-benchmark/bola.db`. Set a PostgreSQL `DATABASE_URL` in the backend process environment for a shared deployment. SQLite data is not automatically copied to PostgreSQL. Python does not automatically load `.env` files. Docker Compose loads the root `.env`.

Redis is optional locally. Set `REDIS_URL` to an empty string to disable it. Tenant quotas use database state if Redis is unavailable.

## Integrate a customer backend

Create a key through the signup website or `POST /v1/signup` with JSON `{"name":"your-project"}` and optional `email`. The response is not cacheable and contains a key shown once. Store it in your server's environment; do not expose it in a browser bundle.

```bash
curl -X POST http://127.0.0.1:8000/v1/authorize \
  -H 'Content-Type: application/json' -H 'X-API-Key: sk_YOUR_KEY' \
  -d '{"subject":"user_123","resource_id":"invoice_456","authorized":true}'
```

`authorized` must be a JSON boolean. Your application remains responsible for ownership rules and enforcing the response. API keys identify tenants; `X-Tenant-ID` does not override that identity.

SDKs are in `cyberaccess-sdk-python`, `cyberaccess-sdk-node`, and `cyberaccess-sdk-go`. These are source packages, not necessarily published to registries. Tenant API keys can manage their own quotas, alert channels, and analytics. The Terraform module uses a newly created tenant's API key automatically; existing tenants supply their own key or tenant-scoped admin JWT.

## Docker and deployment

```bash
docker compose up --build
```

Compose starts PostgreSQL, Redis, backend, frontend, Prometheus, Grafana, and the Django test app. The browser uses `/api`, which nginx proxies to the backend. Set `CYBERACCESS_API_KEY` to a signup-issued key for Django. Configure credentials and ports using `.env.example`.

Production requires PostgreSQL, non-default JWT/login/signup secrets, and explicit allowed origins. Use `DEMO_MODE=false` outside demos. Demo defense toggling requires a demo admin and never disables a customer tenant's defense. Set `VITE_API_BASE_URL` at build time when hosting a static frontend separately from the backend.

Serve the console and `/api` on the same site, using the provided nginx/Vite proxy, with HTTPS in production. Production dashboard cookies are Secure by default and SameSite=Lax. An API hosted on an unrelated site will not receive this cookie; a direct cross-site `VITE_API_BASE_URL` is not a supported console deployment. Do not use a wildcard `FRONTEND_ORIGIN` for the authenticated console. Owners can explicitly replace a lost integration key after confirming their password; replacement immediately revokes the old key. See [tenant dashboard research and design](docs/TENANT_DASHBOARD.md).

## Tests

```powershell
cd bola-benchmark
.\.venv\Scripts\python.exe -m pytest -q
```

Tests use temporary SQLite by default, ignoring the operator's `DATABASE_URL`. To test PostgreSQL, explicitly set `CYBERACCESS_TEST_DATABASE_URL` to a disposable test database. Tests reset demo records. CI tests both database backends. Run SDK tests in their respective directories.

Frontend checks: `cd bola-frontend`, then `npm test`, `npm run lint`, and `npm run build`. The root `npm run build` builds the same frontend.

## Limits

This is a prototype. The subject model uses synthetic training; the endpoint model was trained on another application's data. Threat intelligence is observational. ROI values are estimates based on configurable assumptions. Audit snapshot hashes are not independent compliance certification or proof against database administrators rewriting the ledger. SSE is scoped to a tenant but remains local to one worker; the dashboard polls REST. Account signup is IP-rate-limited but does not verify email ownership. Email verification, password recovery, MFA and team invitations are not implemented.

See `CYBERACCESS_BOLA_COMPLETE_GUIDE.md`, `INTEGRATION_TEST.md`, and SDK READMEs for background; older guides may describe previous implementations.
