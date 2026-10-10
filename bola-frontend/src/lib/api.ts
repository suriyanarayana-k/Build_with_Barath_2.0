const raw = import.meta.env.DEV ? '/api' : (import.meta.env.VITE_API_BASE_URL || '/api');
export const API_BASE = (raw.startsWith('/') || raw.startsWith('http') ? raw : `https://${raw}`).replace(/\/$/, '');

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set('X-CyberAccess-Console', '1');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
    const response = await fetch(`${API_BASE}${path}`, { ...options, credentials: 'include', headers, signal });
    if (response.status === 401 && (path === '/auth/me' || !path.startsWith('/auth/'))) {
      window.dispatchEvent(new Event('cyberaccess:session-expired'));
    }
    // Keep the timeout active until the body arrives, too.
    const body = [204, 205, 304].includes(response.status) ? null : await response.text();
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  } catch (error) {
    if (controller.signal.aborted) throw new Error('The backend did not respond within 10 seconds. Please try again.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function readJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await apiFetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status})`);
  return data;
}

export interface DashboardUser {
  subject: string;
  role: string;
  tenant_id: string;
  tenant_name: string;
  email: string | null;
  capabilities: { demo_controls: boolean; manage_api_key: boolean };
}

export const getSession = async () => (await readJson<{ user: DashboardUser | null }>('/auth/session', { cache: 'no-store' })).user;
export const getAuthOptions = () => readJson<{ password_min_length: number; demo_login_available: boolean }>('/auth/options');
export const loginDashboard = (email: string, password: string, demo = false) => readJson<{ user: DashboardUser }>('/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(demo ? { subject: email, password, console: true } : { email, password }),
});
export const logoutDashboard = () => readJson<{ status: string }>('/auth/logout', { method: 'POST' });
export const claimDashboard = (apiKey: string, email: string, password: string) => readJson<{ user: DashboardUser }>('/auth/claim-tenant', {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
  body: JSON.stringify({ email, password }),
});
export const replaceApiKey = (password: string) => readJson<SignupResult>('/auth/api-key/rotate', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }), cache: 'no-store',
});

export interface QuotaUsage {
  tenant_id: string;
  current_usage: { requests_this_minute: number; requests_per_minute_limit: number; requests_percent: number; audit_events_stored: number };
}
export const getQuotaUsage = (tenantId: string) => readJson<QuotaUsage>(`/tenants/${encodeURIComponent(tenantId)}/quota-usage`);

export interface ConfigResp {
  risk_threshold_block: number;
  risk_threshold_warn: number;
  short_window: number;
  long_window: number;
  rapid_threshold: number;
  slow_threshold: number;
}

export interface StatsResp {
  active_subjects: number;
  blocked_subjects: number;
  // Backend returns {record_id: distinct_subject_count} for records currently
  // under coordinated attack, not a plain count - the dashboard shows the
  // number of distinct records under coordinated attack (Object.keys length).
  coordinated_attacks: Record<string, number>;
}

export interface RiskResp {
  subject: string;
  score: number;
  category: string;
  signals: string[];
  contributions: Record<string, number>;
  is_blocked: boolean;
  strikes?: number;
  lockout_remaining_s?: number;
  lockout_expires_at?: number;
}

export interface AuditEvent {
  id: number;
  occurred_at: number;
  subject_id: string;
  record_id: string;
  detector_decision: string;
  outcome: string;
  explanation: string;
  event_type?: string;
  risk_score?: number;
}

export interface LockoutStatus {
  strike_count: number;
  is_locked: boolean;
  lockout_type?: string;
  lockout_duration_seconds?: number;
  lockout_remaining_seconds: number;
  lockout_expires_at?: number;
  message?: string;
}

// Phase 5: analytics dashboard
export interface AnalyticsOverview {
  tenant_id: string;
  window_hours: number;
  total_events: number;
  outcome_breakdown: Record<string, number>;
  avg_risk_score: number;
  max_risk_score: number;
  unique_subjects_seen: number;
  currently_blocked_subjects: number;
  attacks_blocked: number;
}

// Phase 4: threat detection summary
export interface ThreatSummary {
  tenant_id: string;
  window_hours: number;
  ip_event_breakdown: Record<string, number>;
  flagged_ips: Array<{ ip_address: string; violation_count: number }>;
}

// Phase 5: ROI calculator - see the endpoint's own methodology_note; these are
// operator-configurable assumptions, not verified industry benchmarks.
export interface RoiEstimate {
  tenant_id: string;
  window_days: number;
  methodology_note: string;
  observed: { attacks_blocked: number; requests_denied: number };
  assumptions: {
    cost_per_breach_usd: number;
    breach_probability_per_blocked_attack: number;
    manual_review_minutes_per_event: number;
    engineer_hourly_cost_usd: number;
  };
  estimated_value: {
    breaches_avoided: number;
    breach_cost_avoided_usd: number;
    manual_review_hours_saved: number;
    manual_review_cost_saved_usd: number;
    total_estimated_value_usd: number;
  };
}

export async function getConfig(): Promise<ConfigResp> {
  const res = await apiFetch('/config');
  if (!res.ok) throw new Error(`config: ${res.status}`);
  return res.json();
}

export async function getStats(): Promise<StatsResp> {
  const res = await apiFetch('/stats');
  if (!res.ok) throw new Error(`stats: ${res.status}`);
  return res.json();
}

export async function getRisk(subject: string): Promise<RiskResp> {
  const res = await apiFetch(`/risk/${encodeURIComponent(subject)}`);
  if (!res.ok) throw new Error(`risk: ${res.status}`);
  return res.json();
}

export async function getLockoutStatus(subject: string): Promise<LockoutStatus> {
  const res = await apiFetch(`/lockout-status/${encodeURIComponent(subject)}`);
  if (!res.ok) throw new Error(`lockout: ${res.status}`);
  return res.json();
}

export async function getEvents(): Promise<AuditEvent[]> {
  const res = await apiFetch('/events');
  if (!res.ok) throw new Error(`events: ${res.status}`);
  const data = await res.json();
  return data.events || [];
}

export interface SignupResult {
  tenant_id: string;
  name: string;
  api_key: string;
  warning: string;
  user?: DashboardUser;
}

export async function signup(name: string, email?: string, password?: string): Promise<SignupResult> {
  const res = await apiFetch(password === undefined ? '/v1/signup' : '/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
    cache: 'no-store',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Signup failed (${res.status})`);
  }
  return res.json();
}

export async function getAnalyticsOverview(tenantId: string, windowHours = 24): Promise<AnalyticsOverview> {
  const res = await apiFetch(`/tenants/${encodeURIComponent(tenantId)}/analytics/overview?window_hours=${windowHours}`);
  if (!res.ok) throw new Error(`analytics overview: ${res.status}`);
  return res.json();
}

export async function getThreatSummary(tenantId: string, windowHours = 24): Promise<ThreatSummary> {
  const res = await apiFetch(`/tenants/${encodeURIComponent(tenantId)}/analytics/threat-summary?window_hours=${windowHours}`);
  if (!res.ok) throw new Error(`threat summary: ${res.status}`);
  return res.json();
}

export async function getRoiEstimate(tenantId: string, windowDays = 30): Promise<RoiEstimate> {
  const res = await apiFetch(`/tenants/${encodeURIComponent(tenantId)}/analytics/roi?window_days=${windowDays}`);
  if (!res.ok) throw new Error(`roi estimate: ${res.status}`);
  return res.json();
}

export interface SimResult {
  scenario: string;
  attacker_subject: string;
  total_requests: number;
  blocked_count: number;
  denied_count: number;
  allowed_count: number;
  interception_rate_percent: number;
  peak_risk_score: number;
  verdict: string;
}

// idor_sweep/horizontal_privilege/stealth_creep are safe, repeatable presets -
// These three presets do not touch canary IDs (0, 999999, canary_admin_vault), so none risk a real
// permanent ban on a named demo persona. NORMAL isn't a backend preset - it
// passes bob's own record IDs explicitly so the campaign runner scores a
// legitimate, fully-authorized access pattern instead of an attack. Uses bob,
// not alice: the horizontal_privilege preset below hardcodes alice as its
// attacker, and running it earns her a real (if short) strike lockout - using
// her again for the "NORMAL" baseline would then show a false denial.
const SCENARIOS: Record<string, { scenario_name?: string; attacker_subject?: string; target_records?: string[] }> = {
  NORMAL: { attacker_subject: 'bob', target_records: ['51', '52', '53'] },
  'RAPID BOLA': { scenario_name: 'horizontal_privilege' },
  'LOW & SLOW': { scenario_name: 'stealth_creep' },
  'COORDINATED': { scenario_name: 'idor_sweep' },
  'CANARY PROBE': { scenario_name: 'canary_trap' },
};

export async function runSimulation(kind: keyof typeof SCENARIOS): Promise<SimResult> {
  const payload = SCENARIOS[kind];
  const res = await apiFetch('/redteam/campaign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`campaign: ${res.status}`);
  return res.json();
}

export { SCENARIOS };
