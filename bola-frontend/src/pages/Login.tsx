import { useEffect, useState, type FormEvent } from 'react';
import logoImg from '../assets/logo.png';
import { getAuthOptions, loginDashboard, type DashboardUser } from '../lib/api';

export default function Login({ onLoginSuccess }: { onLoginSuccess: (user: DashboardUser) => void }) {
  const [email, setEmail] = useState('');
  const [subject, setSubject] = useState('');
  const [demo, setDemo] = useState(false);
  const [demoAvailable, setDemoAvailable] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const inputClass = 'w-full px-4 py-3 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25';
  useEffect(() => { getAuthOptions().then(options => setDemoAvailable(options.demo_login_available)).catch(() => {}); }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { user } = await loginDashboard((demo ? subject : email).trim(), password, demo);
      setPassword('');
      onLoginSuccess(user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign in failed');
    } finally {
      setLoading(false);
    }
  };

  return <div className="cyber-grid-bg min-h-screen text-slate-200 flex items-center justify-center p-4">
    <main className="w-full max-w-md border border-cyber-border/60 bg-cyber-panel/95 rounded-xl shadow-2xl p-8">
      <img src={logoImg} alt="" className="h-12 w-12 mb-6" />
      <p className="text-xs font-mono tracking-widest text-cyber-cyan uppercase mb-2">CyberAccess console</p>
      <h1 className="text-2xl font-semibold text-white">Sign in to your dashboard</h1>
      <p className="text-sm text-slate-400 mt-2 mb-6">Your organization's traffic, risk decisions and audit history in one place.</p>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="login-email" className="block text-sm text-slate-300 mb-2">{demo ? 'Demo user ID' : 'Email'}</label>
          <input id="login-email" type={demo ? 'text' : 'email'} autoComplete="username" required
            value={demo ? subject : email} onChange={e => demo ? setSubject(e.target.value) : setEmail(e.target.value)}
            placeholder={demo ? 'Your configured demo user' : 'you@company.com'} className={inputClass} />
        </div>
        <div>
          <label htmlFor="login-password" className="block text-sm text-slate-300 mb-2">Password</label>
          <input id="login-password" type="password" autoComplete="current-password" required value={password}
            onChange={e => setPassword(e.target.value)} className={inputClass} />
        </div>
        {error && <p role="alert" className="p-3 rounded-lg border border-rose-500/30 bg-rose-900/20 text-sm text-rose-300">{error}</p>}
        <button type="submit" disabled={loading} className="w-full rounded-lg bg-cyber-cyan px-4 py-3 text-slate-950 font-semibold disabled:opacity-50">
          {loading ? 'Signing in...' : 'Open dashboard'}
        </button>
      </form>
      <div className="border-t border-slate-700/40 mt-6 pt-5 space-y-3 text-sm text-slate-400">
        <p>New here? <a href="/signup" className="text-cyber-cyan hover:underline">Create your account</a></p>
        <p>Already have an API key? <a href="/claim" className="text-cyber-cyan hover:underline">Enable dashboard access</a></p>
        {demoAvailable && <label className="flex gap-2 items-center text-xs pt-2"><input type="checkbox" checked={demo}
          onChange={e => { setDemo(e.target.checked); setPassword(''); setError(''); }} /> Use a demo user instead</label>}
      </div>
    </main>
  </div>;
}
