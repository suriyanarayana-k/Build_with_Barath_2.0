import { useCallback, useEffect, useRef, useState, useMemo } from 'react';
import {
  getConfig, getStats, getRisk, getEvents, runSimulation, SCENARIOS,
  getAnalyticsOverview, getThreatSummary, getRoiEstimate,
  type ConfigResp, type StatsResp, type RiskResp, type AuditEvent,
  type AnalyticsOverview, type ThreatSummary, type RoiEstimate,
  apiFetch, getSession, logoutDashboard, type DashboardUser,
} from './lib/api';
import { ErrorBoundary } from './components/ErrorBoundary';
import Login from './pages/Login';
import Signup from './pages/Signup';
import TenantAccessCard from './components/TenantAccessCard';

function timeAgo(unixSeconds: number): string {
  if (!unixSeconds) return 'LIVE';
  const diff = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

export default function App() {
  const [user, setUser] = useState<DashboardUser | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const sessionVersion = useRef(0);
  const [online, setOnline] = useState<boolean | null>(null);
  const [config, setConfig] = useState<ConfigResp | null>(null);
  const [stats, setStats] = useState<StatsResp | null>(null);
  const [riskSubject, setRiskSubject] = useState('');
  const [subjectInput, setSubjectInput] = useState('');
  const [risk, setRisk] = useState<RiskResp | null>(null);
  const [riskLoading, setRiskLoading] = useState(false);
  const [simRunning, setSimRunning] = useState<string | null>(null);
  const [simVerdict, setSimVerdict] = useState<string | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsOverview | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null);
  const [roi, setRoi] = useState<RoiEstimate | null>(null);
  const [utcTime, setUtcTime] = useState('');
  const [nowSeconds, setNowSeconds] = useState(() => Math.floor(Date.now() / 1000));
  const [activeBtn, setActiveBtn] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTelemetry = useCallback(() => {
    sessionVersion.current += 1;
    setEvents([]); setAnalytics(null); setThreatSummary(null); setRoi(null);
    setStats(null); setConfig(null); setRisk(null); setRiskSubject(''); setSubjectInput('');
    setOnline(null); setApiError(null); setSimVerdict(null); setSimRunning(null);
    setRiskLoading(false); setActiveBtn(null);
    if (debounceRef.current) clearTimeout(debounceRef.current);
  }, []);

  const handleLoginSuccess = (identity: DashboardUser) => {
    clearTelemetry();
    setUser(identity);
    window.history.replaceState(null, '', '/dashboard');
  };

  const handleLogout = async () => {
    try {
      await logoutDashboard();
      clearTelemetry();
      setUser(null);
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Could not sign out. Please retry.');
    }
  };

  useEffect(() => {
    // Migrate old browser logins without retaining a script-readable token.
    localStorage.removeItem('authToken');
    let stopped = false;
    getSession().then(identity => { if (!stopped) setUser(identity); })
      .catch(() => { if (!stopped) setUser(null); })
      .finally(() => { if (!stopped) setSessionLoading(false); });
    return () => { stopped = true; };
  }, []);

  // UTC Clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().slice(11, 19));
      setNowSeconds(Math.floor(now.getTime() / 1000));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const refreshPassive = useCallback(async () => {
    if (!user) return;
    const version = sessionVersion.current;
    try {
      const [c, s] = await Promise.all([getConfig(), getStats()]);
      if (version !== sessionVersion.current) return;
      setConfig(c);
      setStats(s);
      setOnline(true);
    } catch {
      if (version === sessionVersion.current) setOnline(false);
    }
    try {
      const nextEvents = await getEvents();
      if (version !== sessionVersion.current) return;
      setEvents(nextEvents);
    } catch {
      if (version === sessionVersion.current) setApiError('Could not refresh your audit history.');
    }
    try {
      const [a, t, r] = await Promise.all([getAnalyticsOverview(user.tenant_id), getThreatSummary(user.tenant_id), getRoiEstimate(user.tenant_id)]);
      if (version !== sessionVersion.current) return;
      setAnalytics(a);
      setThreatSummary(t);
      setRoi(r);
    } catch {
      if (version === sessionVersion.current) setApiError('Could not refresh your tenant analytics.');
    }
  }, [user]);

  useEffect(() => {
    if (!user || ['/signup', '/claim'].includes(window.location.pathname)) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await refreshPassive();
      if (!stopped) timer = setTimeout(poll, 3000);
    };
    void poll();
    return () => { stopped = true; clearTimeout(timer); };
  }, [user, refreshPassive]);

  useEffect(() => {
    const expire = () => { clearTelemetry(); setUser(null); };
    window.addEventListener('cyberaccess:session-expired', expire);
    return () => window.removeEventListener('cyberaccess:session-expired', expire);
  }, [clearTelemetry]);

  useEffect(() => () => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
  }, []);

  const fetchRisk = async (subject: string) => {
    const version = sessionVersion.current;
    if (!subject.trim()) {
      setRisk(null);
      setApiError(null);
      return;
    }
    setRiskLoading(true);
    setApiError(null);
    try {
      const nextRisk = await getRisk(subject.trim());
      if (version !== sessionVersion.current) return;
      setRisk(nextRisk);
      setOnline(true);
    } catch (err) {
      if (version !== sessionVersion.current) return;
      setRisk(null);
      setApiError(err instanceof Error ? err.message : 'Failed to fetch risk data');
    } finally {
      if (version === sessionVersion.current) setRiskLoading(false);
    }
  };

  useEffect(() => {
    // Don't auto-fetch; let user type subject
  }, []);

  const onSubjectInput = (val: string) => {
    setSubjectInput(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setRiskSubject(val.trim());
      fetchRisk(val.trim());
    }, 300);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (subjectInput.trim()) {
      setRiskSubject(subjectInput.trim());
      fetchRisk(subjectInput.trim());
    }
  };

  const runSim = async (kind: string) => {
    if (!user?.capabilities.demo_controls) return;
    const version = sessionVersion.current;
    // Handle regular BOLA simulations
    const simKind = kind as keyof typeof SCENARIOS;
    setActiveBtn(kind);
    setTimeout(() => setActiveBtn(null), 300);
    setSimRunning(kind);
    setSimVerdict(null);
    try {
      const res = await runSimulation(simKind);
      if (version !== sessionVersion.current) return;
      setSimVerdict(`${res.verdict} · ${res.interception_rate_percent}% intercepted (${res.blocked_count} blocked, ${res.denied_count} denied of ${res.total_requests})`);
      if (res.attacker_subject) {
        setRiskSubject(res.attacker_subject);
        setSubjectInput(res.attacker_subject);
        await fetchRisk(res.attacker_subject);
      }
      await refreshPassive();
    } catch (err) {
      if (version !== sessionVersion.current) return;
      setSimVerdict(`simulation error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      if (version === sessionVersion.current) setSimRunning(null);
    }
  };

  const resetDemo = async () => {
    if (!user?.capabilities.demo_controls) return;
    const version = sessionVersion.current;
    setActiveBtn('reset');
    setTimeout(() => setActiveBtn(null), 300);
    setSimRunning('RESET');
    try {
      // Call FastAPI reset endpoint - it clears audit_events from database
      const res = await apiFetch('/reset', { method: 'POST' });
      console.log('Reset response:', res.status, res.ok);
      const data = await res.json();
      if (version !== sessionVersion.current) return;
      console.log('Reset result:', data);

      if (!res.ok) {
        setSimVerdict(`Reset failed: ${res.status}`);
        return;
      }

      // Clear ALL frontend state completely - leave dashboard blank
      setRiskSubject('');
      setSubjectInput('');
      setSimVerdict(null);
      setEvents([]);
      setConfig(null);
      setStats(null);
      setRisk(null);
      setRiskLoading(false);
      setOnline(true);
      setApiError(null);
      setActiveBtn(null);

      // Wait before allowing refresh to ensure database is cleared
      await new Promise(r => setTimeout(r, 500));
    } catch (err) {
      setSimVerdict(`Reset error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSimRunning(null);
    }
  };

  // Coordinated attacks calculation
  const attackCount = useMemo(() => {
    if (!stats?.coordinated_attacks) return 0;
    if (typeof stats.coordinated_attacks === 'object') {
      return Object.keys(stats.coordinated_attacks).length;
    }
    return Number(stats.coordinated_attacks) || 0;
  }, [stats]);

  // Risk display calculation
  const riskScore = risk?.score ?? 0;
  const blockThreshold = config?.risk_threshold_block ?? 90;
  const warnThreshold = config?.risk_threshold_warn ?? 70;
  const riskCategory = (risk?.category || (riskScore >= blockThreshold ? 'CRITICAL' : riskScore >= warnThreshold ? 'SUSPICIOUS' : 'NORMAL')).toUpperCase();

  const statusColorConfig = useMemo(() => {
    if (riskScore >= blockThreshold || riskCategory.includes('CRIT') || riskCategory.includes('BLOCK') || riskCategory.includes('ATTACK')) {
      return {
        text: 'text-cyber-crimson',
        bg: 'bg-cyber-crimsonMuted/40',
        border: 'border-cyber-crimson/50',
        pulse: 'bg-rose-500',
        desc: 'High velocity threat detected',
        glow: 'drop-shadow-[0_0_18px_rgba(244,63,94,0.6)]',
        barColor: 'bg-rose-500',
        help: 'Critical threat level - immediate attention required'
      };
    }
    if (riskScore >= warnThreshold || riskCategory.includes('SUSP') || riskCategory.includes('SLOW')) {
      return {
        text: 'text-cyber-orange',
        bg: 'bg-cyber-orangeMuted/40',
        border: 'border-cyber-orange/50',
        pulse: 'bg-amber-500',
        desc: 'Anomalous telemetry flagged',
        glow: 'drop-shadow-[0_0_18px_rgba(245,158,11,0.5)]',
        barColor: 'bg-amber-500',
        help: 'Elevated risk - monitor closely'
      };
    }
    return {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      pulse: 'bg-emerald-400',
      desc: risk ? 'Zero threats flagged' : 'Select a subject to inspect risk',
      glow: 'drop-shadow-[0_0_18px_rgba(255,42,68,0.5)]',
      barColor: 'bg-emerald-400',
      help: 'Normal risk level'
    };
  }, [riskScore, riskCategory, blockThreshold, warnThreshold, risk]);

  // Only observed detector contributions; never invent threat values from the total score.
  const vectorScores = useMemo(() => {
    const contrib = risk?.contributions || {};
    const authVel = Math.min(100, Math.round(Number(contrib.unauthorized_unique_object_pressure ?? contrib.unique_denied_short ?? 0)));
    const anomaly = Math.min(100, Math.round(Number(contrib.ml_behavioral_anomaly ?? 0)));
    const ipRep = Math.min(100, Math.round(Number(contrib.ip_reputation ?? 0)));
    const pattern = Math.min(100, Math.round(Number(contrib.sequential_id_enumeration ?? contrib.low_and_slow_reconnaissance ?? 0)));

    return { authVel, anomaly, ipRep, pattern };
  }, [risk]);

  // Simple pathname-based routing (no router dependency, matching this app's minimal style):
  // /signup is a standalone public page, reachable whether or not the viewer is logged in.
  if (['/signup', '/claim'].includes(window.location.pathname)) {
    return <Signup claim={window.location.pathname === '/claim'} />;
  }

  if (sessionLoading) return <div className="cyber-grid-bg min-h-screen flex items-center justify-center text-slate-300" role="status">Opening your dashboard...</div>;
  // Show login page if not authenticated
  if (!user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="cyber-grid-bg min-h-screen text-slate-200 font-sans flex flex-col selection:bg-rose-900 selection:text-white antialiased">
      {/* BEGIN: MainHeader */}
      <header className="w-full border-b border-cyber-border/80 bg-cyber-panel/85 backdrop-blur-md sticky top-0 z-50">
        <div className="px-6 py-3 flex flex-wrap items-center justify-between gap-4 w-full">
          {/* Shared CyberAccess brand mark */}
          <div className="flex items-center gap-3.5 select-none">
            <img src="/brand/cyberaccess-app-icon.svg" width={48} height={48} alt="" aria-hidden="true" className="w-12 h-12" />
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-100 leading-none select-none">
                  CyberAccess
                </h1>
              </div>
              <p className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-slate-400 font-medium mt-1 select-none flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-cyber-accent animate-pulse"></span>
                BOLA DETECTION <span className="text-neutral-600">•</span> REAL-TIME DEFENSE
              </p>
            </div>
          </div>

          {/* Telemetry & Network Heartbeat Bar */}
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs text-slate-300 max-w-48 truncate" title={user.tenant_name}>{user.tenant_name}</span>
            {/* Heartbeat / Time indicator */}
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md border border-cyber-border bg-[#0a0d14]/70 font-mono text-[11px] text-cyber-textMuted">
              <span className={`w-2 h-2 rounded-full ${online ? 'bg-cyan-400 animate-pulse' : 'bg-slate-600'}`}></span>
              <span className="tracking-wider text-slate-400">
                STATUS: <span className={online ? 'text-cyan-400 font-semibold' : 'text-slate-500 font-semibold'}>{online ? 'ONLINE' : 'OFFLINE'}</span>
              </span>
              <span className="text-neutral-600">|</span>
              <span className="text-slate-400">UTC {utcTime || '12:00:00'}</span>
            </div>

            {/* Connection State Indicator Button */}
            <button
              onClick={() => refreshPassive()}
              title="Click to refresh telemetry"
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md border transition-all shadow-sm group ${
                online
                  ? 'border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20'
                  : 'border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20'
              }`}
              type="button"
            >
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${online ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                <span className={`relative inline-flex rounded-full h-2 w-2 ${online ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
              </span>
              <svg className={`w-3.5 h-3.5 transition-colors ${online ? 'text-emerald-400 group-hover:text-emerald-300' : 'text-amber-500/90 group-hover:text-amber-400'}`} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path d="M5 12.55a11 11 0 0 1 14.08 0"></path>
                <path d="M1.42 9a16 16 0 0 1 21.16 0"></path>
                <path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path>
                <line strokeWidth="3" x1="12" x2="12.01" y1="20" y2="20"></line>
              </svg>
              <span className={`font-mono text-xs font-semibold uppercase tracking-wider ${online ? 'text-emerald-400' : 'text-amber-400'}`}>
                {online ? 'ONLINE' : 'OFFLINE'}
              </span>
            </button>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              title="Sign out of dashboard"
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-md border border-slate-700/50 bg-slate-900/50 hover:bg-slate-800/50 transition-all shadow-sm text-slate-300 hover:text-slate-200"
              type="button"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
              </svg>
              <span className="font-mono text-xs font-semibold uppercase tracking-wider">Logout</span>
            </button>
          </div>
        </div>
      </header>
      {/* END: MainHeader */}

      {/* BEGIN: DashboardLayout (Functional Command Grid) */}
      <main className="flex-1 w-full p-3 sm:p-4 md:p-5 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-3 sm:gap-4 md:gap-5">
        {/* ========================================================================= */}
        {/* COLUMN 1: POSTURE & ENGINE (Left Column - 3 cols) */}
        {/* ========================================================================= */}
        <div className="lg:col-span-3 xl:col-span-3 flex flex-col gap-3 sm:gap-4 md:gap-5">
          {/* BEGIN: SecurityOverviewCard */}
          <ErrorBoundary label="Security Overview">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative overflow-hidden shadow-tactical flex flex-col justify-between flex-1">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-rose-500/40 via-amber-500/30 to-transparent"></div>
              <div>
                <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyber-border/60">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-sm bg-rose-500 shadow-[0_0_8px_#f43f5e]"></span>
                    <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                      SECURITY OVERVIEW
                    </h2>
                  </div>
                  <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                    Live Stats
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div className="rounded-lg bg-[#0a0d14] border border-cyber-border p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors">
                    <div className="flex items-center justify-between">
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
                      <span className="font-mono text-[9px] text-cyber-textMuted tracking-wider">LIVE</span>
                    </div>
                    <div className="font-mono text-3xl font-extrabold text-slate-100 my-2">
                      {stats?.active_subjects ?? 0}
                    </div>
                    <div className="flex flex-col gap-1">
                      <div className="font-mono text-[10px] uppercase font-semibold text-cyber-textMuted tracking-wider">
                        ACTIVE SUBJECTS
                      </div>
                      <span className="font-mono text-[8px] text-slate-500">Users with recent activity</span>
                    </div>
                  </div>

                  <div className="rounded-lg bg-cyber-crimsonMuted/20 border border-cyber-crimson/40 p-3.5 flex flex-col justify-between shadow-glowRed/30 hover:border-cyber-crimson/70 transition-colors">
                    <div className="flex items-center justify-between">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
                      <span className="font-mono text-[9px] text-rose-400/80 tracking-wider">QUARANTINE</span>
                    </div>
                    <div className="font-mono text-3xl font-extrabold text-cyber-crimson my-2">
                      {stats?.blocked_subjects ?? 0}
                    </div>
                    <div className="flex flex-col gap-1">
                      <div className="font-mono text-[10px] uppercase font-semibold text-rose-400 tracking-wider">
                        BLOCKED SUBJECTS
                      </div>
                      <span className="font-mono text-[8px] text-rose-600">3-strike policy lockouts active</span>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg bg-cyber-orangeMuted/20 border border-cyber-orange/40 p-4 shadow-glowOrange/30 hover:border-cyber-orange/70 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <div className="font-mono text-3xl font-extrabold text-cyber-orange">
                      {attackCount}
                    </div>
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold tracking-wider uppercase bg-cyber-orange/10 text-cyber-orange border border-cyber-orange/30">
                      {attackCount} INCIDENTS
                    </span>
                  </div>
                  <div className="flex flex-col gap-1 mb-2">
                    <div className="font-mono text-[11px] uppercase font-semibold text-cyber-orange tracking-wider">
                      COORDINATED ATTACKS DETECTED
                    </div>
                    <span className="font-mono text-[8px] text-amber-600">Multiple subjects on same resource</span>
                  </div>
                  <div className="w-full bg-[#161311] h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-cyber-orange h-full transition-all duration-500"
                      style={{ width: `${Math.min(100, attackCount * 33.3 || (attackCount > 0 ? 100 : 0))}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            </section>
          </ErrorBoundary>

          {/* BEGIN: SystemConfigCard */}
          <ErrorBoundary label="System Config">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex flex-col flex-1">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-cyan-500/40 via-blue-500/20 to-transparent"></div>
              <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyber-border/60">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                    <polyline points="2 17 12 22 22 17"></polyline>
                    <polyline points="2 12 12 17 22 12"></polyline>
                  </svg>
                  <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                    SYSTEM CONFIG
                  </h2>
                </div>
                <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                  Settings
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div className="rounded-lg bg-[#0a0d14] border border-cyber-border/80 p-3 hover:border-slate-700 transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-cyber-textMuted">
                      SHORT WINDOW
                    </span>
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                  </div>
                  <div className="flex items-center gap-2 bg-[#10141e] border border-cyber-border rounded-md px-2.5 py-1.5">
                    <svg className="w-3.5 h-3.5 text-cyber-orange" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <circle cx="12" cy="12" r="10"></circle>
                      <polyline points="12 6 12 12 16 14"></polyline>
                    </svg>
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      {config?.short_window ?? 0}s
                    </span>
                  </div>
                  <span className="block font-mono text-[10px] text-cyber-textMuted mt-2">
                    Threshold: {config?.rapid_threshold ? `${config.rapid_threshold} ` : ''}uniq
                  </span>
                </div>

                <div className="rounded-lg bg-[#0a0d14] border border-cyber-border/80 p-3 hover:border-slate-700 transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-cyber-textMuted">
                      LONG WINDOW
                    </span>
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-500"></span>
                  </div>
                  <div className="flex items-center gap-2 bg-[#10141e] border border-cyber-border rounded-md px-2.5 py-1.5">
                    <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <circle cx="12" cy="12" r="10"></circle>
                      <polyline points="12 6 12 12 16 14"></polyline>
                    </svg>
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      {config?.long_window ?? 0}s
                    </span>
                  </div>
                  <span className="block font-mono text-[10px] text-cyber-textMuted mt-2">
                    Threshold: {config?.slow_threshold ? `${config.slow_threshold} ` : ''}uniq
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-cyber-border/40 flex items-center justify-between text-[10px] font-mono text-cyber-textMuted">
                <span>ALGORITHM: BEHAVIORAL_HEURISTICS</span>
                <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  ENFORCING
                </span>
              </div>
            </section>
          </ErrorBoundary>
        </div>
        {/* END: Column 1 */}

        {/* ========================================================================= */}
        {/* COLUMN 2: PRIMARY COMMAND & SIMULATOR CONSOLE (Center Column - 5 cols) */}
        {/* ========================================================================= */}
        <div className="lg:col-span-5 xl:col-span-5 flex flex-col gap-3 sm:gap-4 md:gap-5">
          {/* BEGIN: LiveRiskMonitorCard */}
          <ErrorBoundary label="Live Risk Monitor">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex flex-col overflow-hidden">
              <div className="absolute -top-16 left-1/2 -translate-x-1/2 w-64 h-64 bg-rose-500/10 rounded-full blur-3xl pointer-events-none"></div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-2 border-b border-cyber-border/60 relative z-10">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-cyber-accent" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path>
                    <circle cx="9" cy="7" r="4"></circle>
                    <path d="M22 21v-2a4 4 0 0 0-3-3.87"></path>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                  </svg>
                  <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-100">
                    LIVE RISK MONITOR
                  </h2>
                </div>

                <form onSubmit={handleSearchSubmit} className="relative w-full sm:w-auto">
                  <svg className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-neutral-500 pointer-events-none" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" x2="16.65" y1="21" y2="16.65"></line>
                  </svg>
                  <input
                    className="w-full bg-[#07090e] border border-cyber-border text-xs rounded-md pl-8 pr-3 py-1.5 text-slate-200 placeholder-neutral-500 focus:outline-none focus:border-rose-500 focus:ring-1 focus:ring-rose-500 font-mono transition-all"
                      placeholder={user.capabilities.demo_controls ? 'Demo subject ID...' : "Your application's user ID..."}
                    type="text"
                    value={subjectInput}
                    onChange={(e) => onSubjectInput(e.target.value)}
                  />
                </form>
              </div>

              {apiError && (
                <div className="rounded-lg bg-rose-950/40 border border-rose-800/60 p-3 mb-4">
                  <p className="font-mono text-xs text-rose-300">
                    ⚠️ {apiError}
                  </p>
                </div>
              )}

              <div className="rounded-xl bg-gradient-to-b from-[#090d15] to-[#06080d] border border-cyber-border/90 p-5 relative overflow-hidden shadow-inner">
                <div className="absolute inset-0 bg-[radial-gradient(#1f293d_1px,transparent_1px)] [background-size:16px_16px] opacity-25 pointer-events-none"></div>
                <div className="relative flex items-center justify-between">
                  <div className="flex flex-col">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-cyber-textMuted font-semibold mb-1">
                      COMPOSITE THREAT SCORE: <span className="text-slate-300 font-mono">{riskSubject || 'N/A'}</span>
                    </span>
                    <div className="flex items-baseline gap-3">
                      <span className={`font-mono text-6xl font-extrabold tracking-tighter ${statusColorConfig.text} ${statusColorConfig.glow}`}>
                        {riskLoading ? (
                          <span className="inline-block animate-spin">◌</span>
                        ) : (
                          riskScore
                        )}
                      </span>
                      <span className="font-mono text-xs text-cyber-textMuted">/ 100</span>
                    </div>
                    {riskLoading && <span className="font-mono text-[10px] text-cyan-400 mt-1">Analyzing...</span>}
                  </div>

                  <div className="flex flex-col items-end">
                    <span className="font-mono text-[9px] uppercase font-bold tracking-widest text-cyber-textMuted mb-1.5">
                      STATUS
                    </span>
                    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-md border ${statusColorConfig.bg} ${statusColorConfig.border}`}>
                      <span className={`w-2 h-2 rounded-full ${statusColorConfig.pulse} animate-pulse`}></span>
                      <span className={`font-mono text-xs font-bold tracking-wider ${statusColorConfig.text}`}>
                        {riskCategory}
                      </span>
                    </div>
                    <span className="font-mono text-[9px] text-cyber-textMuted mt-1">
                      {statusColorConfig.desc}
                    </span>
                    {risk?.is_blocked && (
                      <span className="font-mono text-[9px] text-rose-400 font-bold mt-1.5 px-2 py-0.5 rounded bg-rose-950/40 border border-rose-800/50 animate-pulse">
                        ⏱️ QUARANTINE: {risk.lockout_expires_at ? Math.max(0, risk.lockout_expires_at - nowSeconds) : (risk.lockout_remaining_s || 0)}s
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-cyber-border/60">
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-[10px] uppercase font-bold tracking-widest text-cyber-textMuted">
                    SCORE BREAKDOWN
                  </span>
                  <span className="font-mono text-[9px] text-cyber-textMuted uppercase tracking-wider">
                    Telemetry Vectors
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div className="rounded-lg bg-[#090c13] border border-cyber-border/70 p-2.5">
                    <div className="flex justify-between items-center text-[10px] font-mono mb-1.5">
                      <span className="text-slate-400">Auth Velocity</span>
                      <span className="text-slate-300 font-bold">{vectorScores.authVel}%</span>
                    </div>
                    <div className="w-full bg-[#141a27] h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-cyan-500 h-full transition-all duration-500"
                        style={{ width: `${vectorScores.authVel}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="rounded-lg bg-[#090c13] border border-cyber-border/70 p-2.5">
                    <div className="flex justify-between items-center text-[10px] font-mono mb-1.5">
                      <span className="text-slate-400">Anomaly Vector</span>
                      <span className="text-slate-300 font-bold">{vectorScores.anomaly}%</span>
                    </div>
                    <div className="w-full bg-[#141a27] h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-rose-500 h-full transition-all duration-500"
                        style={{ width: `${vectorScores.anomaly}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="rounded-lg bg-[#090c13] border border-cyber-border/70 p-2.5">
                    <div className="flex justify-between items-center text-[10px] font-mono mb-1.5">
                      <span className="text-slate-400">IP Reputation</span>
                      <span className="text-slate-300 font-bold">{vectorScores.ipRep}%</span>
                    </div>
                    <div className="w-full bg-[#141a27] h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-amber-500 h-full transition-all duration-500"
                        style={{ width: `${vectorScores.ipRep}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="rounded-lg bg-[#090c13] border border-cyber-border/70 p-2.5">
                    <div className="flex justify-between items-center text-[10px] font-mono mb-1.5">
                      <span className="text-slate-400">Pattern Match</span>
                      <span className="text-slate-300 font-bold">{vectorScores.pattern}%</span>
                    </div>
                    <div className="w-full bg-[#141a27] h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-purple-500 h-full transition-all duration-500"
                        style={{ width: `${vectorScores.pattern}%` }}
                      ></div>
                    </div>
                  </div>
                </div>

                {risk?.contributions && Object.keys(risk.contributions).length > 0 && (
                  <div className="mt-3 pt-2 border-t border-cyber-border/30 space-y-1">
                    {Object.entries(risk.contributions).map(([key, val]) => (
                      <div key={key} className="flex items-center justify-between text-[10px] font-mono">
                        <span className="text-cyber-textMuted uppercase">{key.replace(/_/g, ' ')}</span>
                        <span className="text-cyber-crimson font-bold">+{Number(val)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>
          </ErrorBoundary>

          {/* BEGIN: LiveSimulatorCard (Tactical Suite) */}
          {!user.capabilities.demo_controls && <TenantAccessCard key={user.tenant_id} user={user} eventCount={analytics?.total_events ?? events.length} />}
          {user.capabilities.demo_controls && <ErrorBoundary label="Live Simulator">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-5 relative shadow-tactical flex flex-col flex-1">
              <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyber-border/60">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-cyber-orange" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                  </svg>
                  <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-100">
                    LIVE SIMULATOR
                  </h2>
                </div>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[9px] font-mono tracking-wider font-semibold text-rose-400 bg-rose-950/40 border border-rose-900/60 shadow-glowRed/20">
                  ATTACK TESTS
                </span>
              </div>

              <p className="font-mono text-[11px] text-cyber-textMuted mb-3">
                Run attack tests to see how the system defends:
              </p>

              <div className="grid grid-cols-2 gap-3 mb-3">
                <button
                  disabled={simRunning !== null}
                  onClick={() => runSim('RAPID BOLA')}
                  className={`btn-tactical group relative rounded-lg border border-rose-800/80 bg-gradient-to-b from-rose-950/40 to-[#120b10] p-3 text-center shadow-glowRed/20 hover:border-rose-500 hover:shadow-glowRed active:bg-rose-900/40 disabled:opacity-50 ${
                    activeBtn === 'RAPID BOLA' ? 'ring-2 ring-rose-500/60' : ''
                  }`}
                  type="button"
                >
                  <div className="flex items-center justify-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e]"></span>
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-rose-400 group-hover:text-rose-300 transition-colors">
                      {simRunning === 'RAPID BOLA' ? 'RUNNING...' : 'RAPID BOLA'}
                    </span>
                  </div>
                  <span className="block font-mono text-[9px] text-rose-400/70 mt-1">Rapid Sequential Access</span>
                </button>

                <button
                  disabled={simRunning !== null}
                  onClick={() => runSim('LOW & SLOW')}
                  className={`btn-tactical group relative rounded-lg border border-amber-600/70 bg-gradient-to-b from-amber-950/30 to-[#14100b] p-3 text-center shadow-glowOrange/20 hover:border-amber-500 hover:shadow-glowOrange active:bg-amber-950/40 disabled:opacity-50 ${
                    activeBtn === 'LOW & SLOW' ? 'ring-2 ring-amber-500/60' : ''
                  }`}
                  type="button"
                >
                  <div className="flex items-center justify-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_8px_#f59e0b]"></span>
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-amber-500 group-hover:text-amber-400 transition-colors">
                      {simRunning === 'LOW & SLOW' ? 'RUNNING...' : 'LOW & SLOW'}
                    </span>
                  </div>
                  <span className="block font-mono text-[9px] text-amber-500/70 mt-1">Slow Evasion Attack</span>
                </button>

                <button
                  disabled={simRunning !== null}
                  onClick={() => runSim('COORDINATED')}
                  className={`btn-tactical group relative rounded-lg border border-rose-800/80 bg-gradient-to-b from-rose-950/40 to-[#120b10] p-3 text-center shadow-glowRed/20 hover:border-rose-500 hover:shadow-glowRed active:bg-rose-900/40 disabled:opacity-50 ${
                    activeBtn === 'COORDINATED' ? 'ring-2 ring-rose-500/60' : ''
                  }`}
                  type="button"
                >
                  <div className="flex items-center justify-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e]"></span>
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-rose-400 group-hover:text-rose-300 transition-colors">
                      {simRunning === 'COORDINATED' ? 'RUNNING...' : 'COORDINATED'}
                    </span>
                  </div>
                  <span className="block font-mono text-[9px] text-rose-400/70 mt-1">Coordinated Multi-User Attack</span>
                </button>

                <button
                  disabled={simRunning !== null}
                  onClick={() => runSim('CANARY PROBE')}
                  className={`btn-tactical group relative rounded-lg border border-pink-800/80 bg-gradient-to-b from-pink-950/40 to-[#140810] p-3 text-center shadow-glowRed/20 hover:border-pink-500 hover:shadow-glowRed active:bg-pink-900/40 disabled:opacity-50 ${
                    activeBtn === 'CANARY PROBE' ? 'ring-2 ring-pink-500/60' : ''
                  }`}
                  type="button"
                >
                  <div className="flex items-center justify-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-pink-500 shadow-[0_0_8px_#ec4899]"></span>
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-pink-400 group-hover:text-pink-300 transition-colors">
                      CANARY PROBE
                    </span>
                  </div>
                  <span className="block font-mono text-[9px] text-pink-400/70 mt-1">Trap URL Detection</span>
                </button>
              </div>

              {simVerdict && (
                <div className="p-2.5 rounded-lg bg-[#0a0d14] border border-cyber-border mb-3 font-mono text-[11px] text-slate-300 leading-relaxed text-center">
                  {simVerdict}
                </div>
              )}

              <div className="mt-auto pt-2">
                <button
                  disabled={simRunning !== null}
                  onClick={resetDemo}
                  className={`btn-tactical w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-[#0a0d14] hover:bg-[#131926] border border-cyber-border hover:border-neutral-500 text-slate-300 hover:text-white transition-all shadow-tactical disabled:opacity-50 ${
                    activeBtn === 'reset' ? 'ring-2 ring-rose-500/60' : ''
                  }`}
                  type="button"
                >
                  <svg className={`w-4 h-4 text-slate-400 group-hover:rotate-180 transition-transform duration-500 ${simRunning === 'RESET' ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
                    <path d="M21 3v5h-5"></path>
                    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
                    <path d="M8 16H3v5"></path>
                  </svg>
                  <span className="font-mono text-xs font-bold uppercase tracking-wider">
                    RESET DEMO
                  </span>
                </button>
              </div>
            </section>
          </ErrorBoundary>}
        </div>
        {/* END: Column 2 */}

        {/* ========================================================================= */}
        {/* COLUMN 3: AUDIT LEDGER & STREAM (Right Column - 4 cols) */}
        {/* ========================================================================= */}
        <div className="lg:col-span-4 xl:col-span-4 flex flex-col">
          <ErrorBoundary label="Audit Timeline">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex-1 flex flex-col min-h-[400px] sm:min-h-[500px] md:min-h-[580px]">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/30 to-rose-500/30"></div>

              <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyber-border/60">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
                  </svg>
                  <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                    AUDIT TIMELINE
                  </h2>
                </div>
                <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                  Event Ledger
                </span>
              </div>

              <div className="flex items-center justify-between bg-[#080b11] border border-cyber-border rounded-lg px-3 py-2 mb-3 text-[11px] font-mono">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span className="text-slate-400">STREAM:</span>
                  <span className="text-slate-200 font-semibold">ALL_CHANNELS</span>
                </div>
                <span className="text-cyber-textMuted">BUFFER: {events.length}/1000</span>
              </div>

              {events.length > 0 && (
                <div className="rounded-lg bg-[#080b11] border border-cyber-border/60 p-3 mb-3">
                  <div className="text-[9px] font-mono uppercase font-semibold text-cyber-textMuted mb-2 tracking-wider">
                    EVENT TYPE LEGEND
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-[10px] font-mono">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                      <span className="text-slate-300">Quarantine Timer</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                      <span className="text-slate-300">Admin Breach</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                      <span className="text-slate-300">Blocked</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-pink-500"></span>
                      <span className="text-slate-300">Canary</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-violet-500"></span>
                      <span className="text-slate-300">404 Probe</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
                      <span className="text-slate-300">Denied</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-400"></span>
                      <span className="text-slate-300">Threat Signal</span>
                    </div>
                  </div>
                </div>
              )}

              {events.length === 0 ? (
                <div className="flex-1 rounded-xl border border-dashed border-cyber-border bg-[#06080e]/80 relative flex flex-col items-center justify-center p-4 sm:p-6 md:p-8 overflow-hidden">
                  <div className="relative w-40 h-40 mb-5 flex items-center justify-center">
                    <div className="absolute inset-0 rounded-full border border-cyber-border/70"></div>
                    <div className="absolute inset-4 rounded-full border border-cyber-border/50"></div>
                    <div className="absolute inset-10 rounded-full border border-cyber-border/30"></div>
                    <div className="absolute inset-x-0 top-1/2 h-[1px] bg-cyber-border/40"></div>
                    <div className="absolute inset-y-0 left-1/2 w-[1px] bg-cyber-border/40"></div>
                    <div className="absolute inset-0 rounded-full radar-sweep pointer-events-none opacity-40"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_10px_#f43f5e]"></div>
                  </div>

                  <div className="text-center relative z-10 max-w-xs">
                    <span className="font-mono text-sm font-semibold text-slate-300 tracking-wider block mb-1">
                      No events recorded.
                    </span>
                    <p className="font-mono text-[11px] text-cyber-textMuted leading-relaxed">
                      {user.capabilities.demo_controls ? 'Waiting for activity. Run a test to see events here.' : 'Waiting for your application. Connect your backend to see your authorization activity here.'}
                    </p>
                  </div>

                </div>
              ) : (
                <div className="flex-1 overflow-y-auto space-y-2.5 max-h-[640px] pr-1">
                  {events.map((ev) => {
                    const isThreatSignal = ev.event_type === 'threat_signal' || ev.record_id === 'threat_signal';
                    const isTimer = ev.event_type === 'quarantine_timer' || ev.record_id?.includes('timer') || ev.record_id?.includes('quarantine');
                    const isAdmin = ev.event_type === 'admin_probe' || ev.record_id?.includes('admin');
                    const isBlocked = ev.outcome === 'blocked';
                    const isDenied = ev.outcome === 'denied';
                    const is404 = ev.event_type === '404_probe' || ev.record_id?.includes('404') || ev.record_id?.startsWith('record_') || ev.record_id?.startsWith('item_');
                    const isCanary = ev.event_type === 'canary_trap' || ev.record_id?.includes('canary');
                    return (
                      <div
                        key={ev.id}
                        className={`p-2.5 rounded-lg border text-xs font-mono transition-all hover:translate-x-0.5 ${
                          isThreatSignal
                            ? 'bg-fuchsia-950/30 border-fuchsia-500/50'
                            : isTimer
                            ? 'bg-cyan-950/25 border-cyan-500/50'
                            : isAdmin
                            ? 'bg-red-950/40 border-red-500/70'
                            : isBlocked
                            ? 'bg-cyber-crimsonMuted/20 border-cyber-crimson/50'
                            : isCanary
                            ? 'bg-pink-900/20 border-pink-500/50'
                            : is404
                            ? 'bg-violet-900/20 border-violet-500/50'
                            : isDenied
                            ? 'bg-cyber-orangeMuted/20 border-cyber-orange/40'
                            : 'bg-[#090c13] border-cyber-border'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 flex-1">
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              isThreatSignal ? 'bg-fuchsia-400 animate-pulse' : isTimer ? 'bg-cyan-400 animate-pulse' : isAdmin ? 'bg-red-500 animate-pulse' : isBlocked ? 'bg-rose-500' : isCanary ? 'bg-pink-400' : is404 ? 'bg-violet-400' : isDenied ? 'bg-amber-500' : 'bg-emerald-400'
                            }`}></span>
                            <span className="font-bold text-slate-200 truncate">{ev.subject_id}</span>
                          </div>
                          <span className="text-cyber-textMuted text-[9px] whitespace-nowrap ml-2">{timeAgo(ev.occurred_at)}</span>
                        </div>
                        <div className="mt-1.5 space-y-1">
                          <div className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase tracking-wider flex-shrink-0 ${
                              isThreatSignal
                                ? 'bg-fuchsia-500/20 text-fuchsia-300'
                                : isTimer
                                ? 'bg-cyan-500/20 text-cyan-300'
                                : isAdmin
                                ? 'bg-red-500/30 text-red-200'
                                : isBlocked
                                ? 'bg-rose-500/20 text-rose-300'
                                : isCanary
                                ? 'bg-pink-500/20 text-pink-300'
                                : is404
                                ? 'bg-violet-500/20 text-violet-300'
                                : isDenied
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-emerald-500/10 text-emerald-400'
                            }`}>
                              {isThreatSignal ? 'THREAT' : isTimer ? 'QUARANTINE' : isAdmin ? 'ADMIN' : isBlocked ? 'BLOCKED' : isCanary ? 'CANARY' : is404 ? 'PROBE' : isDenied ? 'DENIED' : 'ALLOWED'}
                            </span>
                            <span className="text-[9px] text-cyber-textMuted flex-1">
                              {isThreatSignal ? (ev.explanation || 'Threat signal detected').split(' | ')[0] :
                               isTimer ? (() => {
                                const strikeMatch = ev.explanation?.match(/Strike (\d+)\/3/);
                                const strikeNum = strikeMatch ? strikeMatch[1] : '?';
                                return `Strike ${strikeNum}/3 remaining`;
                              })() :
                               isBlocked ? `Rapid access detected` :
                               is404 ? `Object enumeration` :
                               isCanary ? `Trap triggered` :
                               isAdmin ? `Admin portal probe` :
                               isDenied ? `Unauthorized access` :
                               `Normal access`}
                            </span>
                          </div>
                          <div className="text-[8px] text-cyber-textMuted pl-3.5 flex items-center gap-2">
                            <span>
                              Triggered: {
                                isThreatSignal ? 'ip/geo/tls/behavioral' :
                                is404 ? 'enum' :
                                isCanary ? 'honeypot' :
                                isAdmin ? 'admin' :
                                isDenied ? 'no auth' :
                                isBlocked ? 'high risk' :
                                'normal'
                              }
                            </span>
                            {isTimer && ev.explanation?.includes('remaining') && (
                              <span className="text-rose-400 font-bold">
                                {ev.explanation?.match(/\d+s remaining/)?.[0] || '—'}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </ErrorBoundary>
        </div>
        {/* END: Column 3 */}

        {/* ========================================================================= */}
        {/* ROW 2: PHASE 4/5 INTELLIGENCE (Analytics, Threat Detection, ROI) - full width */}
        {/* ========================================================================= */}
        <div className="lg:col-span-12 grid grid-cols-1 md:grid-cols-3 gap-3 sm:gap-4 md:gap-5">
          {/* BEGIN: AnalyticsOverviewCard (Phase 5) */}
          <ErrorBoundary label="Analytics Overview">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex flex-col">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-cyan-500/40 via-blue-500/20 to-transparent"></div>
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyber-border/60">
                <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                  Analytics Overview
                </h2>
                <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                  {analytics ? `${analytics.window_hours}h window` : '24h window'}
                </span>
              </div>
              {analytics ? (
                <div className="grid grid-cols-2 gap-2.5 text-center">
                  <div className="rounded-lg bg-[#0a0d14] border border-cyber-border p-2.5">
                    <div className="font-mono text-2xl font-extrabold text-slate-100">{analytics.total_events}</div>
                    <div className="font-mono text-[9px] uppercase text-cyber-textMuted tracking-wider mt-1">Total Events</div>
                  </div>
                  <div className="rounded-lg bg-cyber-crimsonMuted/20 border border-cyber-crimson/40 p-2.5">
                    <div className="font-mono text-2xl font-extrabold text-cyber-crimson">{analytics.attacks_blocked}</div>
                    <div className="font-mono text-[9px] uppercase text-rose-400 tracking-wider mt-1">Attacks Blocked</div>
                  </div>
                  <div className="rounded-lg bg-[#0a0d14] border border-cyber-border p-2.5">
                    <div className="font-mono text-2xl font-extrabold text-slate-100">{analytics.avg_risk_score.toFixed(1)}</div>
                    <div className="font-mono text-[9px] uppercase text-cyber-textMuted tracking-wider mt-1">Avg Risk Score</div>
                  </div>
                  <div className="rounded-lg bg-[#0a0d14] border border-cyber-border p-2.5">
                    <div className="font-mono text-2xl font-extrabold text-slate-100">{analytics.unique_subjects_seen}</div>
                    <div className="font-mono text-[9px] uppercase text-cyber-textMuted tracking-wider mt-1">Unique Subjects</div>
                  </div>
                </div>
              ) : (
                <p className="font-mono text-[11px] text-cyber-textMuted text-center py-6">Loading...</p>
              )}
            </section>
          </ErrorBoundary>
          {/* END: AnalyticsOverviewCard */}

          {/* BEGIN: ThreatIntelCard (Phase 4) */}
          <ErrorBoundary label="Threat Intelligence">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex flex-col">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-amber-500/40 via-rose-500/20 to-transparent"></div>
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyber-border/60">
                <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                  Threat Intelligence
                </h2>
                <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                  IP Reputation
                </span>
              </div>
              {threatSummary ? (
                threatSummary.flagged_ips.length > 0 ? (
                  <div className="space-y-1.5 overflow-y-auto max-h-40">
                    {threatSummary.flagged_ips.map((ip) => (
                      <div key={ip.ip_address} className="flex items-center justify-between rounded-lg bg-cyber-crimsonMuted/20 border border-cyber-crimson/40 px-2.5 py-1.5">
                        <span className="font-mono text-[11px] text-slate-200 truncate">{ip.ip_address}</span>
                        <span className="font-mono text-[10px] font-bold text-cyber-crimson">{ip.violation_count} violations</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center py-6 text-center">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 mb-2"></span>
                    <p className="font-mono text-[11px] text-emerald-400">No flagged IPs</p>
                    <p className="font-mono text-[9px] text-cyber-textMuted mt-1">
                      {Object.entries(threatSummary.ip_event_breakdown).map(([k, v]) => `${k}: ${v}`).join(' · ') || 'No IP events yet'}
                    </p>
                  </div>
                )
              ) : (
                <p className="font-mono text-[11px] text-cyber-textMuted text-center py-6">Loading...</p>
              )}
            </section>
          </ErrorBoundary>
          {/* END: ThreatIntelCard */}

          {/* BEGIN: RoiCalculatorCard (Phase 5) */}
          <ErrorBoundary label="ROI Calculator">
            <section className="rounded-xl bg-cyber-panel border border-cyber-border p-3 sm:p-4 md:p-5 relative shadow-tactical flex flex-col">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-500/40 via-cyan-500/20 to-transparent"></div>
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-cyber-border/60">
                <h2 className="font-mono text-xs uppercase font-bold tracking-widest text-slate-200">
                  ROI Estimate
                </h2>
                <span className="font-mono text-[9px] uppercase tracking-wider px-2 py-0.5 rounded bg-[#131926] text-cyber-textMuted border border-cyber-border">
                  {roi ? `${roi.window_days}d window` : '30d window'}
                </span>
              </div>
              {roi ? (
                <>
                  <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3 text-center mb-2.5">
                    <div className="font-mono text-2xl font-extrabold text-emerald-400">
                      ${roi.estimated_value.total_estimated_value_usd.toLocaleString()}
                    </div>
                    <div className="font-mono text-[9px] uppercase text-emerald-400/80 tracking-wider mt-1">Estimated Value Delivered</div>
                  </div>
                  <div className="flex items-center justify-between font-mono text-[10px] text-cyber-textMuted mb-1">
                    <span>Manual review hours saved</span>
                    <span className="text-slate-200 font-semibold">{roi.estimated_value.manual_review_hours_saved}h</span>
                  </div>
                  <div className="flex items-center justify-between font-mono text-[10px] text-cyber-textMuted">
                    <span>Breaches avoided (est.)</span>
                    <span className="text-slate-200 font-semibold">{roi.estimated_value.breaches_avoided}</span>
                  </div>
                  <p className="font-mono text-[8px] text-cyber-textMuted/70 mt-2.5 pt-2 border-t border-cyber-border/40 leading-relaxed">
                    Illustrative estimate from configurable assumptions, not a verified benchmark.
                  </p>
                </>
              ) : (
                <p className="font-mono text-[11px] text-cyber-textMuted text-center py-6">Loading...</p>
              )}
            </section>
          </ErrorBoundary>
          {/* END: RoiCalculatorCard */}
        </div>
        {/* END: Row 2 */}
      </main>
      {/* END: DashboardLayout */}
    </div>
  );
}
