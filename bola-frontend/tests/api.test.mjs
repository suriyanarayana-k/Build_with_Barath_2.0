import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';

const source = readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8')
  .replaceAll('import.meta.env', '({ DEV: true })');
const compiled = ts.transpile(source, { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 });
const api = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'));
const storage = new Map();
globalThis.localStorage = {
  getItem: key => storage.get(key) || null,
  setItem: (key, value) => storage.set(key, value),
  removeItem: key => storage.delete(key),
};
globalThis.window = new EventTarget();

test('signup uses POST JSON through the same-origin proxy', async () => {
  storage.clear();
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/v1/signup');
    assert.equal(options.method, 'POST');
    assert.deepEqual(JSON.parse(options.body), { name: 'company', email: 'test@example.com' });
    assert.equal(options.headers.has('Authorization'), false);
    return Response.json({ tenant_id: 'tenant', api_key: 'sk_test' });
  };
  assert.equal((await api.signup('company', 'test@example.com')).api_key, 'sk_test');
});

test('dashboard uses cookie credentials without exposing a token to JavaScript', async () => {
  storage.set('authToken', 'obsolete-session-token');
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/events');
    assert.equal(options.headers.has('Authorization'), false);
    assert.equal(options.credentials, 'include');
    assert.equal(options.headers.get('X-CyberAccess-Console'), '1');
    return Response.json({ events: [{ id: 1, risk_score: 37 }] });
  };
  assert.equal((await api.getEvents())[0].risk_score, 37);
});

test('expired sessions notify the login screen', async () => {
  let expired = false;
  window.addEventListener('cyberaccess:session-expired', () => { expired = true; }, { once: true });
  globalThis.fetch = async () => Response.json({ detail: 'expired' }, { status: 401 });
  assert.equal((await api.apiFetch('/auth/me')).status, 401);
  assert.equal(expired, true);
});

test('account signup creates a dashboard login without storing the API key', async () => {
  storage.clear();
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/auth/signup');
    assert.deepEqual(JSON.parse(options.body), { name: 'Company', email: 'owner@example.test', password: 'test-password-123' });
    assert.equal(options.credentials, 'include');
    return Response.json({ tenant_id: 'customer', api_key: 'shown-once', user: { tenant_id: 'customer' } });
  };
  assert.equal((await api.signup('Company', 'owner@example.test', 'test-password-123')).user.tenant_id, 'customer');
  assert.equal(storage.size, 0);
});

test('all analytics helpers request the supplied tenant instead of demo', async () => {
  const paths = [];
  globalThis.fetch = async url => { paths.push(url); return Response.json({ tenant_id: 'customer' }); };
  await api.getAnalyticsOverview('customer');
  await api.getThreatSummary('customer');
  await api.getRoiEstimate('customer');
  assert.equal(paths.length, 3);
  for (const path of paths) assert.match(path, /^\/api\/tenants\/customer\/analytics\//);
});

test('invalid login or replacement password does not expire a valid session', async () => {
  let expired = false;
  const listener = () => { expired = true; };
  window.addEventListener('cyberaccess:session-expired', listener);
  globalThis.fetch = async () => Response.json({ detail: 'Invalid password' }, { status: 401 });
  await assert.rejects(api.replaceApiKey('wrong'), /Invalid password/);
  await assert.rejects(api.loginDashboard('owner@example.test', 'wrong'), /Invalid password/);
  assert.equal(expired, false);
  window.removeEventListener('cyberaccess:session-expired', listener);
});

test('legacy tenant claim sends its key only in the request header', async () => {
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/auth/claim-tenant');
    assert.equal(options.headers.get('X-API-Key'), 'legacy-key');
    assert.deepEqual(JSON.parse(options.body), { email: 'owner@example.test', password: 'test-password-123' });
    return Response.json({ user: { tenant_id: 'legacy-tenant' } });
  };
  assert.equal((await api.claimDashboard('legacy-key', 'owner@example.test', 'test-password-123')).user.tenant_id, 'legacy-tenant');
});

test('session restore handles both returning users and guests', async () => {
  globalThis.fetch = async url => {
    assert.equal(url, '/api/auth/session');
    return Response.json({ user: { tenant_id: 'customer' } });
  };
  assert.equal((await api.getSession()).tenant_id, 'customer');
  globalThis.fetch = async () => Response.json({ user: null });
  assert.equal(await api.getSession(), null);
});

test('unresponsive requests time out and release the pending operation', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  globalThis.fetch = async (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  });
  const pending = assert.rejects(api.signup('company'), /within 10 seconds/);
  mock.timers.tick(10000);
  await pending;
  mock.timers.reset();
});

test('caller cancellation does not disable the request timeout', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  const caller = new AbortController();
  globalThis.fetch = async (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  });
  const pending = assert.rejects(api.apiFetch('/config', { signal: caller.signal }), /within 10 seconds/);
  mock.timers.tick(10000);
  await pending;
  assert.equal(caller.signal.aborted, false);
  mock.timers.reset();
});

test('canary button calls the supported campaign endpoint', async () => {
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/redteam/campaign');
    assert.equal(options.method, 'POST');
    assert.deepEqual(JSON.parse(options.body), { scenario_name: 'canary_trap' });
    return Response.json({ scenario: 'canary_trap' });
  };
  assert.equal((await api.runSimulation('CANARY PROBE')).scenario, 'canary_trap');
});
