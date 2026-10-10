import { lazy, Suspense, useEffect, useState } from 'react';
import { getSession, logoutDashboard, type DashboardUser } from './lib/api';
import Login from './pages/Login';
import Signup from './pages/Signup';
import TenantConsole from './components/TenantConsole';
import './console.css';

const DemoDashboard = lazy(() => import('./DemoDashboard'));

export default function App() {
  const [user, setUser] = useState<DashboardUser | null>(null);
  const [opening, setOpening] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [demoTools, setDemoTools] = useState(false);
  useEffect(() => { if (demoTools) document.title = 'Demo tools | CyberAccess'; }, [demoTools]);
  useEffect(() => {
    let stopped = false;
    localStorage.removeItem('authToken');
    getSession().then(identity => { if (!stopped) setUser(identity); })
      .catch(() => { if (!stopped) setSessionError('Could not connect to the backend. Retry to check your session.'); })
      .finally(() => { if (!stopped) setOpening(false); });
    const expire = () => { setUser(null); setDemoTools(false); setSessionError('Your session expired. Sign in again.'); };
    window.addEventListener('cyberaccess:session-expired', expire);
    return () => { stopped = true; window.removeEventListener('cyberaccess:session-expired', expire); };
  }, []);
  const signOut = async () => {
    await logoutDashboard();
    setUser(null); setDemoTools(false); setSessionError('');
    window.history.replaceState(null, '', '/login');
  };
  if (['/signup', '/claim'].includes(window.location.pathname)) return <Signup claim={window.location.pathname === '/claim'} />;
  if (opening) return <main className="cc-opening" role="status">Opening your dashboard…</main>;
  if (!user) return <><Login onLoginSuccess={identity => {
    setUser(identity); setSessionError(''); window.history.replaceState(null, '', '/dashboard');
  }} />{sessionError && <div className="cc-session-notice" role="alert">{sessionError}<button onClick={() => window.location.reload()}>Retry</button></div>}</>;
  if (demoTools && user.capabilities.demo_controls) return <><div className="cc-demo-return"><button onClick={async () => { try { setUser(await getSession()); setDemoTools(false); } catch { setSessionError('Could not restore your session. Please retry.'); } }}>← Return to tenant console</button></div><Suspense fallback={<p>Opening demo tools…</p>}><DemoDashboard /></Suspense></>;
  return <TenantConsole key={user.tenant_id + user.subject} user={user} onSignOut={signOut} onDemoTools={() => setDemoTools(true)} />;
}
