# Lost & Found: API-key-only integration

The portal's Django server calls CyberAccess with `X-API-Key`. It does not need a
CyberAccess user JWT, tenant signup key, admin credential, or access to the CyberAccess
database. Django continues to authenticate its own users and decide who owns each claim.

## Configure

The portal is pinned as a Git submodule pointing to the maintained Lost & Found fork.
Include it when cloning the platform:

```shell
git clone --recurse-submodules https://github.com/BUILD-WITH-BARATH/Build_with_Barath_2.0.git
```

For an existing clone, run `git submodule update --init Lost-foundbyKM` from the
platform root. The pinned commit keeps the tested integration reproducible.

Create a tenant account on the CyberAccess website and copy the one-time key from
**API access** into `Lost-foundbyKM/.env` (this file is ignored by Git):

```dotenv
CYBERACCESS_API_KEY=sk_your_tenant_key
CYBERACCESS_API_URL=http://127.0.0.1:8017
CYBERACCESS_ENABLED=true
CYBERACCESS_FAIL_OPEN=false
```

Use your deployed CyberAccess URL when running outside this local preview. The API key
is the only integration credential; the URL specifies where to send requests.

Install `Lost-foundbyKM/requirements.txt`, then start the portal:

```powershell
cd Lost-foundbyKM
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8001 --noreload
```

Restart Django after replacing the key or changing integration settings.

## Request flow

1. Django authenticates the portal user and checks resource ownership.
2. The adapter sends subject ID, object ID, ownership boolean, endpoint and method.
3. CyberAccess returns allow/deny/block, risk score and behavioral signals, and stores
   the event in the tenant's audit history.
4. The portal enforces the response before displaying private claim information or
   accepting a protected mutation.

The integration sends no claim proof, contact details or portal passwords to CyberAccess.
CyberAccess receives authorization metadata, not the claim contents. The API key stays on
the Django server and is never included in browser responses.

## Local interactive demonstration

The current preview uses a dedicated **Lost & Found Portal demo** tenant, a real generated
tenant key in the portal's ignored server environment, and a disposable portal database.
The original tracked portal database is preserved.

Open <http://127.0.0.1:8001/cyberaccess/demo/>:

1. Choose **Use Alice** or **Use Mallory**. These synthetic users need no password.
2. **Check my claim**: local ownership passes; ordinary traffic is allowed.
3. **Try another claim**: ownership fails; access is denied.
4. **Run enumeration test**: up to ten real denied API requests increase behavioral risk.
   The table displays the actual score and signals; it stops when quarantine triggers.
5. Follow the actual claim-page links to verify enforcement in the original portal UI.
6. Sign in to the demo tenant's CyberAccess dashboard and open **Activity**. Local
   dashboard account details are in `.gstack/lost-found-demo/dashboard-login.txt`.

These controls never reset the central risk engine or release a quarantine. Wait for the
cooldown or choose the other synthetic user. The demo UI requires loopback access,
`DEBUG=True`, and `CYBERACCESS_DEMO_ENABLED=true`. Keep demo controls disabled in deployments.
The legacy unauthenticated reset/defense-toggle routes are disabled by default.

To seed another disposable demo database, set `DJANGO_DATABASE_PATH`, enable
`CYBERACCESS_DEMO_ENABLED=true`, migrate, and run `manage.py seed_cyberaccess_demo`.

## Outages and bad keys

The default is fail-closed. The portal denies access when CyberAccess cannot evaluate
a request and displays a service-unavailable page instead of inventing a risk score.
An unavailable quarantine-status lookup also stops authenticated protected pages and
writes before their views execute. Login, logout, registration and each user's own
notification inbox remain available. Profile and password routes are covered by the
quarantine gate. Missing-object probes use the same HTTP 503 fallback during outages.
The demo table labels fallback results and returns HTTP 503. Invalid/revoked API keys
deny access even when optional fail-open mode is enabled. In fail-open mode, outages
can allow locally authorized requests; local ownership denials always remain denied.

Quarantine is scoped to the tenant and stable portal user ID. One user's lockout does
not lock every other user sharing their network address.

## Security notifications and block page

Live `deny` and `block` API decisions create a security notice in the requesting user's
existing portal notification inbox and show a warning in the portal. Another user's
inbox and private claim contents remain inaccessible. Repeated denials are grouped
for a configurable cooldown; repeated blocks with the same server expiry reuse one
notice for the entire quarantine. Ordinary allowed traffic does not generate alerts.

The HTTP 403 block page displays the decision and a countdown based on the API's
expiry. It preserves the actual score at block for the same user, session and
quarantine; a fresh session omits the score when the status API does not supply one.
**Check access again** always asks the server; reaching zero on the
browser timer cannot release a quarantine. Users can read their own notifications
and sign out while protected pages stay blocked. The local demo also shows each
security message immediately and links to the actual block page after a block.

The Django server logs denied/blocked decisions as JSON containing only subject ID,
object ID, endpoint, decision, source, risk score and bounded signals. The same API
calls remain visible in CyberAccess **Activity**. Service outages are labelled
`local_fallback` and never presented as attack notifications. Configure:

```dotenv
CYBERACCESS_NOTIFICATIONS_ENABLED=true
CYBERACCESS_NOTIFICATION_COOLDOWN_SECONDS=60
CYBERACCESS_LOG_ALLOWED=false
# Optional local rotating file, in addition to console logs:
CYBERACCESS_SECURITY_LOG_FILE=path/to/ignored/cyberaccess-security.log
```

The current local demo writes its server security log under the ignored
`.gstack/lost-found-demo/` directory. This integration uses existing notification
tables and server logging; it needs no paid service or additional API credential.

## Tests

```powershell
cd Lost-foundbyKM
$env:CYBERACCESS_ENABLED = 'false'
.\.venv\Scripts\python.exe manage.py test accounts items claims audit lost_found_project --noinput
```

The adapter tests mock HTTP. They cover key-only authentication, local ownership precedence,
malformed responses, missing/shared keys, fail-open/fail-closed behavior and URL encoding.
Portal tests cover private claims and receipts, mutation authorization, behavioral blocks,
per-user quarantine, outage pages, edit/delete enforcement and local-only demo access.
Reserved demo usernames cannot sign in as staff, superusers or password-based accounts.
All 47 tests use an isolated Django database.
