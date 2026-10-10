import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { LayoutDashboard, ListFilter, Users, KeyRound, Gauge, BookOpen, LogOut, RefreshCw, Menu, X, Search, ArrowRight, CircleCheck, CircleX, ShieldAlert, Info, Clock, Copy } from 'lucide-react';
import {
  API_BASE, getAnalyticsOverview, getConfig, getEvents, getQuotaUsage, getRisk,
  type AnalyticsOverview, type AuditEvent, type ConfigResp, type DashboardUser, type QuotaUsage, type RiskResp,
} from '../lib/api';
import { decisionLabel, readConsoleView, riskText, visibleEvents, type ConsoleView } from '../lib/console-data';
import TenantAccessCard from './TenantAccessCard';
import MeasuredText from './MeasuredText';
import BrandMark from './BrandMark';

const links = [
  ['overview', 'Overview', LayoutDashboard], ['activity', 'Activity', ListFilter],
  ['subjects', 'Subjects', Users], ['api-access', 'API access', KeyRound],
  ['usage', 'Usage', Gauge], ['documentation', 'Documentation', BookOpen],
] as const;
const titles = { overview: 'Security overview', activity: 'Activity', subjects: 'Subjects', 'api-access': 'API access', usage: 'Usage', documentation: 'Integration guide' };
const fmt = (value?: number) => value === undefined ? '—' : value.toLocaleString();
const when = (seconds: number) => new Date(seconds * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });

function Badge({ outcome }: { outcome: string }) {
  const Icon = outcome === 'blocked' ? ShieldAlert : outcome === 'denied' ? CircleX : outcome === 'allowed' ? CircleCheck : Info;
  return <span className={'cc-badge ' + (['allowed', 'denied', 'blocked'].includes(outcome) ? outcome : 'neutral')}><Icon size={14} aria-hidden="true" />{decisionLabel(outcome)}</span>;
}

function QuotaCard({ usage, detailed = false }: { usage: QuotaUsage | null; detailed?: boolean }) {
  const current = usage?.current_usage;
  return <section className="cc-card">
    <div className="cc-card-heading"><h2>Current minute quota</h2><Gauge size={18} aria-hidden="true" /></div>
    <MeasuredText className="cc-muted">Current window usage, separate from your activity totals.</MeasuredText>
    <div className="cc-quota-number">{fmt(current?.requests_this_minute)} <span>/ {fmt(current?.requests_per_minute_limit)} checks</span></div>
    {current && <><div className="cc-progress" role="progressbar" aria-label="Current quota used" aria-valuenow={Math.min(current.requests_this_minute, current.requests_per_minute_limit)} aria-valuemin={0} aria-valuemax={current.requests_per_minute_limit} aria-valuetext={`${current.requests_this_minute} of ${current.requests_per_minute_limit} checks`}><span style={{ width: Math.max(0, Math.min(100, current.requests_percent)) + '%' }} /></div><p className="cc-muted">{current.requests_percent.toFixed(1)}% of the configured limit</p></>}
    {detailed && <div className="cc-separated"><h3>Stored audit events</h3><p className="cc-large-number">{fmt(current?.audit_events_stored)}</p><MeasuredText className="cc-muted">Total stored for this tenant, across all time ranges.</MeasuredText></div>}
  </section>;
}

function EventInspector({ event, investigate }: { event: AuditEvent | null; investigate: (subject: string) => void }) {
  return <section className="cc-card cc-inspector" aria-label="Event details">
    <p className="cc-eyebrow">INVESTIGATION VIEW</p><h2>Event detail</h2>
    {!event ? <MeasuredText className="cc-muted">Select an event to see its decision and explanation.</MeasuredText> : <>
      <p className="cc-muted"><Clock size={14} aria-hidden="true" /> {when(event.occurred_at)}</p>
      <dl className="cc-fields"><div><dt>Subject</dt><dd>{event.subject_id || '—'}</dd></div><div><dt>Resource</dt><dd>{event.record_id || '—'}</dd></div></dl>
      <div className="cc-decision"><Badge outcome={event.outcome} /><strong>{riskText(event.risk_score)} <small>/ 100</small></strong></div>
      <p className="cc-muted">Risk recorded at decision time</p>
      <h3>Recorded explanation</h3><MeasuredText className="cc-explanation">{event.explanation || 'No explanation was recorded.'}</MeasuredText>
      <dl className="cc-fields"><div><dt>Detector decision</dt><dd>{event.detector_decision || '—'}</dd></div><div><dt>Audit event</dt><dd>#{event.id}</dd></div></dl>
      {event.subject_id && <button className="cc-button cc-secondary cc-full" onClick={() => investigate(event.subject_id)}>Inspect current subject <ArrowRight size={16} /></button>}
    </>}
  </section>;
}

function EventTable({ events, selected, onSelect, loading }: { events: AuditEvent[]; selected: number | null; onSelect: (id: number) => void; loading: boolean }) {
  if (!events.length) return <div className="cc-empty" role="status"><ListFilter size={30} aria-hidden="true" /><h3>{loading ? 'Loading your activity…' : 'No matching events'}</h3><p>{loading ? 'Checking your tenant’s audit history.' : 'Try another filter or time range. New tenants can connect their backend from API access.'}</p></div>;
  return <div className="cc-table-scroll"><table className="cc-table"><caption className="cc-sr-only">Tenant audit events. Inspect opens event details.</caption><thead><tr><th>Time</th><th>Subject</th><th>Resource</th><th>Decision</th><th>Risk</th><th><span className="cc-sr-only">Details</span></th></tr></thead><tbody>{events.map(event => <tr key={event.id} className={event.id === selected ? 'is-selected' : ''}>
    <td><time dateTime={new Date(event.occurred_at * 1000).toISOString()} title={when(event.occurred_at)}>{new Date(event.occurred_at * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</time></td>
    <td className="cc-id">{event.subject_id || '—'}</td><td className="cc-id">{event.record_id || '—'}</td><td><Badge outcome={event.outcome} /></td><td>{riskText(event.risk_score)}</td><td><button className="cc-inspect-button" aria-pressed={event.id === selected} onClick={() => onSelect(event.id)}>Inspect</button></td>
  </tr>)}</tbody></table></div>;
}

export default function TenantConsole({ user, onSignOut, onDemoTools }: { user: DashboardUser; onSignOut: () => Promise<void>; onDemoTools: () => void }) {
  const [view, setView] = useState<ConsoleView>(() => readConsoleView());
  useEffect(() => { document.title = `${titles[view]} | CyberAccess`; }, [view]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [hours, setHours] = useState(() => {
    const value = Number(new URLSearchParams(window.location.search).get('hours'));
    return [1, 24, 168].includes(value) ? value : 24;
  });
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.search).get('q') || '');
  const [outcome, setOutcome] = useState(() => new URLSearchParams(window.location.search).get('outcome') || '');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsOverview | null>(null);
  const [usage, setUsage] = useState<QuotaUsage | null>(null);
  const [config, setConfig] = useState<ConfigResp | null>(null);
  const [refreshing, setRefreshing] = useState(true);
  const [error, setError] = useState('');
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [subject, setSubject] = useState('');
  const [risk, setRisk] = useState<RiskResp | null>(null);
  const [riskError, setRiskError] = useState('');
  const [riskLoading, setRiskLoading] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [copied, setCopied] = useState(false);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const requestVersion = useRef(0);
  const riskVersion = useRef(0);
  const mainRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const invalidateRequests = useCallback(() => { requestVersion.current++; riskVersion.current++; }, []);
  const invalidateTelemetry = useCallback(() => { requestVersion.current++; }, []);
  const closeMenu = useCallback(() => { setMenuOpen(false); requestAnimationFrame(() => menuRef.current?.focus()); }, []);
  useEffect(() => {
    if (!menuOpen) return;
    const frame = requestAnimationFrame(() => sidebarRef.current?.querySelector<HTMLButtonElement>('.cc-mobile-close')?.focus());
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); closeMenu(); return; }
      if (event.key !== 'Tab') return;
      const controls = sidebarRef.current?.querySelectorAll<HTMLElement>('a[href], button:not(:disabled)');
      if (!controls?.length) return;
      const first = controls[0], last = controls[controls.length - 1];
      if (!sidebarRef.current?.contains(document.activeElement)) { event.preventDefault(); first.focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    const wide = window.matchMedia('(min-width: 761px)');
    const resize = () => { if (wide.matches) { setMenuOpen(false); requestAnimationFrame(() => mainRef.current?.focus()); } };
    wide.addEventListener('change', resize);
    document.addEventListener('keydown', keydown);
    return () => { cancelAnimationFrame(frame); wide.removeEventListener('change', resize); document.removeEventListener('keydown', keydown); };
  }, [menuOpen, closeMenu]);
  useEffect(() => {
    const back = () => {
      setView(readConsoleView()); setMenuOpen(false);
      const params = new URLSearchParams(window.location.search);
      setAnalytics(null); setUpdatedAt(null);
      const value = Number(params.get('hours')); setHours([1, 24, 168].includes(value) ? value : 24);
      setQuery(params.get('q') || ''); setOutcome(params.get('outcome') || '');
    };
    window.addEventListener('popstate', back);
    return () => { window.removeEventListener('popstate', back); invalidateRequests(); };
  }, [invalidateRequests]);
  const navigate = (next: ConsoleView) => {
    setView(next); setMenuOpen(false);
    window.history.pushState(null, '', '/dashboard/' + next + window.location.search);
    requestAnimationFrame(() => mainRef.current?.focus());
  };
  const filter = (nextHours: number, nextQuery: string, nextOutcome: string) => {
    if (nextHours !== hours) { setAnalytics(null); setUpdatedAt(null); }
    setNow(Date.now() / 1000);
    setHours(nextHours); setQuery(nextQuery); setOutcome(nextOutcome);
    const params = new URLSearchParams();
    params.set('hours', String(nextHours)); if (nextQuery) params.set('q', nextQuery); if (nextOutcome) params.set('outcome', nextOutcome);
    window.history.replaceState(null, '', window.location.pathname + '?' + params);
  };
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    setNow(Date.now() / 1000);
    setRefreshing(true);
    const results = await Promise.allSettled([getAnalyticsOverview(user.tenant_id, hours), getEvents(), getQuotaUsage(user.tenant_id), getConfig()]);
    if (version !== requestVersion.current) return;
    const [a, e, q, c] = results;
    if (a.status === 'fulfilled') setAnalytics(a.value);
    if (e.status === 'fulfilled') setEvents(e.value);
    if (q.status === 'fulfilled') setUsage(q.value);
    if (c.status === 'fulfilled') setConfig(c.value);
    const failures = results.map((r, i) => r.status === 'rejected' ? ['summary', 'activity', 'quota', 'configuration'][i] : '').filter(Boolean);
    setError(failures.length ? 'Could not refresh ' + failures.join(', ') + '. Previously loaded values may be out of date. Retry to update them.' : '');
    if (!failures.length) setUpdatedAt(new Date());
    setRefreshing(false);
  }, [user.tenant_id, hours]);
  useEffect(() => {
    let stopped = false, timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (document.visibilityState !== 'hidden') await refresh();
      if (!stopped) timer = setTimeout(poll, 15000);
    };
    void poll();
    return () => { stopped = true; clearTimeout(timer); invalidateTelemetry(); };
  }, [refresh, invalidateTelemetry]);
  const inspectSubject = async (id: string) => {
    const clean = id.trim(); if (!clean) return;
    setSubject(clean); setRisk(null); setRiskError(''); setRiskLoading(true); navigate('subjects');
    const version = ++riskVersion.current;
    try { const result = await getRisk(clean); if (version === riskVersion.current) setRisk(result); }
    catch (err) { if (version === riskVersion.current) setRiskError(err instanceof Error ? err.message : 'Subject lookup failed.'); }
    finally { if (version === riskVersion.current) setRiskLoading(false); }
  };
  const shown = visibleEvents(events, hours, now, query, outcome);
  const tableRows = view === 'overview' ? shown.slice(0, 8) : shown;
  const selected = tableRows.find(event => event.id === selectedId) || tableRows[0] || null;
  const recentSubjects = [...new Set(shown.map(event => event.subject_id).filter(Boolean))];
  const outcomes = Object.entries(analytics?.outcome_breakdown || {});
  const base = API_BASE.startsWith('http') ? API_BASE : window.location.origin + API_BASE;
  const snippet = 'const response = await fetch("' + base + '/v1/authorize", {\n  method: "POST",\n  headers: {\n    "Content-Type": "application/json",\n    "X-API-Key": process.env.CYBERACCESS_API_KEY\n  },\n  body: JSON.stringify({\n    subject: user.id,\n    resource_id: resource.id,\n    authorized: resource.owner_id === user.id\n  })\n});\nconst result = await response.json();\nif (!response.ok || result.decision !== "allow") {\n  throw new Error("Access denied");\n}';
  const signOut = async () => {
    setSigningOut(true);
    try { await onSignOut(); } catch { setError('Could not sign out. Please retry.'); setSigningOut(false); }
  };
  return <div className="cc-shell">
    <a className="cc-skip" href="#console-main">Skip to content</a>
    {menuOpen && <button className="cc-backdrop" tabIndex={-1} aria-label="Close navigation" onClick={closeMenu} />}
    <aside ref={sidebarRef} className={'cc-sidebar' + (menuOpen ? ' is-open' : '')} role={menuOpen ? 'dialog' : undefined} aria-modal={menuOpen || undefined} aria-label="Primary navigation">
      <div className="cc-brand"><BrandMark />CyberAccess<button className="cc-mobile-close" aria-label="Close navigation" onClick={closeMenu}><X size={20} /></button></div>
      <div className="cc-tenant"><span className="cc-avatar">{user.tenant_name.slice(0, 1).toUpperCase()}</span><div><strong>{user.tenant_name}</strong><small>Your tenant</small></div></div>
      <nav>{links.map(([id, label, Icon]) => <a key={id} href={'/dashboard/' + id + window.location.search} aria-current={view === id ? 'page' : undefined} onClick={e => { if (!e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey && e.button === 0) { e.preventDefault(); navigate(id); } }}><Icon size={18} aria-hidden="true" />{label}</a>)}</nav>
      <div className="cc-account"><strong>{user.email || user.subject}</strong><small>{user.tenant_name}</small>{user.capabilities.demo_controls && <button className="cc-text-button" onClick={onDemoTools}>Open demo tools</button>}<button onClick={signOut} disabled={signingOut}><LogOut size={17} />{signingOut ? 'Signing out…' : 'Sign out'}</button><small className="cc-version">CyberAccess console</small></div>
    </aside>
    <div className="cc-workspace" inert={menuOpen}>
      <header className="cc-topbar"><button ref={menuRef} className="cc-menu" aria-label="Open navigation" aria-expanded={menuOpen} onClick={() => setMenuOpen(true)}><Menu size={22} /></button><div className="cc-breadcrumb"><span>{user.tenant_name}</span><span>/</span><strong>{titles[view]}</strong></div><div className="cc-refresh-controls"><label className="cc-sr-only" htmlFor="time-range">Activity time range</label><select id="time-range" value={hours} onChange={e => filter(Number(e.target.value), query, outcome)}><option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select><span className="cc-updated" aria-live="polite">{refreshing ? 'Refreshing…' : updatedAt ? 'Updated ' + updatedAt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : 'Not refreshed'}</span><button className="cc-button cc-secondary" disabled={refreshing} onClick={() => void refresh()}><RefreshCw size={15} className={refreshing ? 'cc-spin' : ''} />Refresh</button></div></header>
      <main id="console-main" ref={mainRef} tabIndex={-1} className="cc-main">
        <div className="cc-page-heading"><div><p className="cc-eyebrow">{user.tenant_name}</p><h1>{titles[view]}</h1><p className="cc-muted">{view === 'overview' ? 'Your authorization activity, with the evidence behind every decision.' : view === 'activity' ? 'Inspect the latest recorded decisions for your tenant.' : view === 'subjects' ? 'Look up a subject’s current behavioral risk and block status.' : view === 'api-access' ? 'Connect your backend and manage your integration credential.' : view === 'usage' ? 'Current quota usage and stored audit history.' : 'Keep your integration simple and your ownership rules explicit.'}</p></div></div>
        {error && <div className="cc-alert" role="alert"><CircleX size={18} /><span>{error}</span><button disabled={refreshing} onClick={() => void refresh()}>Retry</button></div>}
        {view === 'overview' && <>
          <div className="cc-notice"><Info size={18} /><span>Keep ownership checks in your backend. CyberAccess adds behavioral checks.</span></div>
          <div className="cc-stats">{[
            ['Audit events', fmt(analytics?.total_events), 'In the selected period', ListFilter],
            ['Denied events', fmt(analytics ? analytics.outcome_breakdown.denied || 0 : undefined), 'Recorded denials', CircleX],
            ['Blocked subjects', fmt(analytics?.currently_blocked_subjects), 'Currently blocked, across periods', ShieldAlert],
            ['Average risk', analytics && analytics.total_events > 0 ? riskText(analytics.avg_risk_score) + ' / 100' : '—', 'Mean risk of recorded events', Gauge],
          ].map(([label, value, description, Icon]) => {
            const MetricIcon = Icon as typeof Gauge;
            return <section className="cc-card cc-stat" key={String(label)}><div><h2>{String(label)}</h2><MetricIcon size={18} /></div><strong>{String(value)}</strong><MeasuredText className="cc-muted">{String(description)}</MeasuredText></section>;
          })}</div>
          <div className="cc-content-grid"><div className="cc-card"><div className="cc-card-heading"><h2>Decision summary</h2><span className="cc-muted">{fmt(analytics?.total_events)} audit events</span></div>{outcomes.length ? <><div className="cc-outcomes">{outcomes.map(([name, count]) => <div key={name}><Badge outcome={name} /><strong>{fmt(count)}</strong></div>)}</div><div className="cc-breakdown" aria-hidden="true">{outcomes.map(([name, count]) => <span key={name} className={name} style={{ flexGrow: count }} />)}</div><p className="cc-muted">Counts reflect event outcomes. Blocked events and currently blocked subjects are different measures.</p></> : <MeasuredText className="cc-muted">{refreshing ? 'Loading your summary…' : 'Waiting for your first recorded event. Connect your backend from API access.'}</MeasuredText>}</div><QuotaCard usage={usage} /></div>
        </>}
        {(view === 'overview' || view === 'activity') && <div className="cc-content-grid cc-activity-grid"><section className="cc-card cc-activity"><div className="cc-card-heading"><h2>{view === 'overview' ? 'Recent activity' : 'Audit activity'}</h2>{view === 'overview' && <button className="cc-text-button" onClick={() => navigate('activity')}>View activity <ArrowRight size={15} /></button>}</div><div className="cc-filters"><label className="cc-search"><Search size={16} aria-hidden="true" /><input aria-label="Filter loaded events by subject, resource or explanation" placeholder="Subject, resource or explanation…" value={query} onChange={e => filter(hours, e.target.value, outcome)} /></label><select aria-label="Filter by decision" value={outcome} onChange={e => filter(hours, query, e.target.value)}><option value="">All decisions</option>{[...new Set(events.map(event => event.outcome))].map(value => <option value={value} key={value}>{decisionLabel(value)}</option>)}</select></div><EventTable events={tableRows} selected={selected?.id ?? null} onSelect={setSelectedId} loading={refreshing} /><p className="cc-table-note">Showing {tableRows.length} matches from the latest {events.length} loaded events (API limit: 100). Filters apply to this loaded history.</p></section><EventInspector event={selected} investigate={id => void inspectSubject(id)} /></div>}
        {view === 'subjects' && <div className="cc-content-grid"><section className="cc-card"><h2>Investigate a subject</h2><form className="cc-subject-form" onSubmit={(e: FormEvent) => { e.preventDefault(); void inspectSubject(subject); }}><label htmlFor="subject-id">Subject ID</label><div><input id="subject-id" className="cc-input" required value={subject} onChange={e => setSubject(e.target.value)} placeholder="Enter an ID from your application" /><button className="cc-button" disabled={riskLoading}>{riskLoading ? 'Checking…' : 'Look up'}</button></div></form>{riskError && <p role="alert" className="cc-error">{riskError}</p>}{risk && <><div className="cc-decision"><h3>{risk.subject}</h3><strong>{riskText(risk.score)} / 100</strong></div><p><span className={'cc-badge ' + (risk.is_blocked ? 'blocked' : 'neutral')}>{risk.is_blocked ? <ShieldAlert size={14} aria-hidden="true" /> : <Info size={14} aria-hidden="true" />}{risk.is_blocked ? 'Currently blocked' : 'Not currently blocked'}</span> <span className="cc-muted">{risk.category}</span></p><p className="cc-muted">Current risk may differ from the score recorded on an earlier event.</p><h3>Returned signals</h3>{risk.signals.length ? <ul className="cc-signal-list">{risk.signals.map((signal, i) => <li key={i}>{signal}</li>)}</ul> : <p className="cc-muted">No active signals returned.</p>}<dl className="cc-fields">{Object.entries(risk.contributions).map(([name, value]) => <div key={name}><dt>{name.replaceAll('_', ' ')}</dt><dd>{fmt(value)}</dd></div>)}</dl>{risk.is_blocked && <p className="cc-muted">Lockout remaining: {fmt(risk.lockout_remaining_s)} seconds</p>}</>}</section><section className="cc-card"><h2>Subjects in loaded activity</h2><p className="cc-muted">IDs seen in the selected period within the latest 100 audit events.</p><div className="cc-subject-list">{recentSubjects.map(id => <button key={id} onClick={() => void inspectSubject(id)}><span>{id}</span><ArrowRight size={16} /></button>)}</div>{!recentSubjects.length && <p className="cc-muted">No subjects in the loaded history.</p>}</section></div>}
        {view === 'api-access' && <TenantAccessCard user={user} eventCount={0} />}
        {view === 'usage' && <div className="cc-content-grid"><QuotaCard usage={usage} detailed /><section className="cc-card"><h2>Behavioral thresholds</h2><MeasuredText className="cc-muted">These are the current thresholds returned by the backend.</MeasuredText><dl className="cc-fields"><div><dt>Warn at risk</dt><dd>{fmt(config?.risk_threshold_warn)} / 100</dd></div><div><dt>Block at risk</dt><dd>{fmt(config?.risk_threshold_block)} / 100</dd></div><div><dt>Short observation window</dt><dd>{fmt(config?.short_window)} seconds</dd></div><div><dt>Long observation window</dt><dd>{fmt(config?.long_window)} seconds</dd></div></dl></section></div>}
        {view === 'documentation' && <section className="cc-card cc-docs"><div className="cc-card-heading"><h2>Authorize before returning a resource</h2><button className="cc-button cc-secondary" onClick={async () => { try { await navigator.clipboard.writeText(snippet); setCopied(true); } catch { setError('Copy is unavailable. Select the example and copy it manually.'); } }}><Copy size={15} />{copied ? 'Copied' : 'Copy example'}</button></div><MeasuredText className="cc-muted">Store your API key in a server environment variable. Check resource ownership in your application, send that result to CyberAccess, and enforce the response before returning data.</MeasuredText><pre>{snippet}</pre><div className="cc-notice"><Info size={18} /><span>Use your real authorization rules for “authorized”. Never trust a value supplied by the caller.</span></div><h3>Dashboard access</h3><p>Your email and password restore your dashboard session. Your integration API key stays on your server and is shown only when it is issued or replaced.</p><button className="cc-text-button" onClick={() => navigate('api-access')}>Manage API access <ArrowRight size={16} /></button></section>}
      </main>
    </div>
  </div>;
}
