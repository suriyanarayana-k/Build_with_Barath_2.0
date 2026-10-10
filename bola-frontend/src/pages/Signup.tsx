import { useEffect, useState, type FormEvent } from 'react';
import logoImg from '../assets/logo.png';
import { claimDashboard, getAuthOptions, signup, type SignupResult } from '../lib/api';

export default function Signup({ claim = false }: { claim?: boolean }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [passwordMinLength, setPasswordMinLength] = useState(12);
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SignupResult | null>(null);
  const [claimed, setClaimed] = useState(false);
  const [copied, setCopied] = useState(false);
  const inputClass = 'w-full px-4 py-3 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25';
  useEffect(() => { getAuthOptions().then(options => setPasswordMinLength(options.password_min_length)).catch(() => {}); }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    if (password !== confirmation) { setError('Passwords must match.'); return; }
    setLoading(true);
    try {
      if (claim) {
        await claimDashboard(apiKey.trim(), email.trim(), password);
        setApiKey('');
        setClaimed(true);
      } else {
        setResult(await signup(name.trim(), email.trim(), password));
      }
      setPassword('');
      setConfirmation('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Account creation failed');
    } finally {
      setLoading(false);
    }
  };

  const copyKey = async () => {
    if (!result) return;
    try { await navigator.clipboard.writeText(result.api_key); setCopied(true); }
    catch { setError('Copy is unavailable in this browser. Select the key and copy it manually.'); }
  };

  return <div className="cyber-grid-bg min-h-screen text-slate-200 flex items-center justify-center p-4 py-10">
    <main className="w-full max-w-md border border-cyber-border/60 bg-cyber-panel/95 rounded-xl shadow-2xl p-8">
      <img src={logoImg} alt="" className="h-12 w-12 mb-6" />
      <p className="text-xs font-mono tracking-widest text-cyber-cyan uppercase mb-2">CyberAccess console</p>
      {result || claimed ? <>
        <h1 className="text-2xl font-semibold text-white">Your dashboard is ready</h1>
        <p className="text-sm text-slate-400 mt-2 mb-6">You can return anytime by signing in with your email and password.</p>
        {result && <>
          <p className="text-sm text-slate-300 mb-3">Organization: <strong>{result.name}</strong></p>
          <p className="p-3 rounded-lg border border-amber-500/30 bg-amber-900/20 text-sm text-amber-300 mb-4">{result.warning}</p>
          <label htmlFor="new-api-key" className="block text-sm text-slate-300 mb-2">Server API key</label>
          <div className="flex gap-2 mb-4">
            <input id="new-api-key" type="text" readOnly value={result.api_key} onFocus={e => e.target.select()}
              className={`${inputClass} min-w-0 font-mono text-xs`} />
            <button type="button" onClick={copyKey} className="px-4 rounded-lg bg-slate-800 text-cyber-cyan">{copied ? 'Copied' : 'Copy'}</button>
          </div>
          <p className="text-xs text-slate-400 mb-6">Keep the key in your backend's secret storage. Your browser dashboard uses your account session.</p>
        </>}
        {claimed && <p className="text-sm text-slate-300 mb-6">Your existing key continues to work. No integration changes are needed.</p>}
        {error && <p role="alert" className="text-rose-300 text-sm mb-3">{error}</p>}
        <a href="/dashboard" className="block text-center rounded-lg bg-cyber-cyan px-4 py-3 text-slate-950 font-semibold">
          {result ? "I've saved my key · Open dashboard" : 'Open dashboard'}
        </a>
      </> : <>
        <h1 className="text-2xl font-semibold text-white">{claim ? 'Enable dashboard access' : 'Create your organization'}</h1>
        <p className="text-sm text-slate-400 mt-2 mb-6">{claim ? 'Connect your existing tenant to an account using its API key.' : 'Get an API key and a private security dashboard. Free, with no approval needed.'}</p>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label htmlFor="signup-organization" className="block text-sm text-slate-300 mb-2">{claim ? 'Existing API key' : 'Company / project name'}</label>
            <input id="signup-organization" type={claim ? 'password' : 'text'} required maxLength={200}
              autoComplete={claim ? 'off' : 'organization'} value={claim ? apiKey : name}
              onChange={e => claim ? setApiKey(e.target.value) : setName(e.target.value)}
              placeholder={claim ? 'sk_...' : 'Acme'} className={inputClass} />
          </div>
          <div>
            <label htmlFor="signup-email" className="block text-sm text-slate-300 mb-2">Email</label>
            <input id="signup-email" type="email" autoComplete="username" required maxLength={254} value={email}
              onChange={e => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} />
          </div>
          <div>
            <label htmlFor="signup-password" className="block text-sm text-slate-300 mb-2">Create a password</label>
            <input id="signup-password" type="password" autoComplete="new-password" minLength={passwordMinLength} maxLength={72} required
              value={password} onChange={e => setPassword(e.target.value)} aria-describedby="password-help" className={inputClass} />
            <p id="password-help" className="text-xs text-slate-500 mt-2">Use at least {passwordMinLength} characters.</p>
          </div>
          <div>
            <label htmlFor="signup-confirm" className="block text-sm text-slate-300 mb-2">Confirm password</label>
            <input id="signup-confirm" type="password" autoComplete="new-password" required value={confirmation}
              onChange={e => setConfirmation(e.target.value)} className={inputClass} />
          </div>
          {error && <p role="alert" className="p-3 rounded-lg border border-rose-500/30 bg-rose-900/20 text-sm text-rose-300">{error}</p>}
          <button type="submit" disabled={loading} className="w-full rounded-lg bg-cyber-cyan px-4 py-3 text-slate-950 font-semibold disabled:opacity-50">
            {loading ? 'Creating your account...' : claim ? 'Enable dashboard' : 'Create account & API key'}
          </button>
        </form>
        <div className="border-t border-slate-700/40 mt-6 pt-5 space-y-3 text-sm text-slate-400">
          <p>Have an account? <a href="/login" className="text-cyber-cyan hover:underline">Sign in</a></p>
          <p>{claim ? 'Need a new tenant?' : 'Already have a key?'} <a href={claim ? '/signup' : '/claim'} className="text-cyber-cyan hover:underline">{claim ? 'Create an account' : 'Enable dashboard access'}</a></p>
        </div>
      </>}
    </main>
  </div>;
}
