import { useEffect, useState, type FormEvent } from 'react';
import { API_BASE, getQuotaUsage, replaceApiKey, type DashboardUser, type QuotaUsage, type SignupResult } from '../lib/api';

export default function TenantAccessCard({ user, eventCount }: { user: DashboardUser; eventCount: number }) {
  const [usage, setUsage] = useState<QuotaUsage | null>(null);
  const [error, setError] = useState('');
  const [replacing, setReplacing] = useState(false);
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [replacement, setReplacement] = useState<SignupResult | null>(null);
  const [copied, setCopied] = useState(false);
  const base = API_BASE.startsWith('http') ? API_BASE : `${window.location.origin}${API_BASE}`;

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const result = await getQuotaUsage(user.tenant_id);
        if (!stopped) setUsage(result);
      } catch { if (!stopped) setError('Could not refresh your quota usage.'); }
      if (!stopped) timer = setTimeout(refresh, 10000);
    };
    void refresh();
    return () => { stopped = true; clearTimeout(timer); };
  }, [user.tenant_id]);

  const replace = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    setPending(true);
    try {
      setReplacement(await replaceApiKey(password));
      setReplacing(false);
      setPassword('');
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not replace the key.'); }
    finally { setPending(false); }
  };

  const snippet = `const response = await fetch("${base}/v1/authorize", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": process.env.CYBERACCESS_API_KEY
  },
  body: JSON.stringify({
    subject: user.id,
    resource_id: resource.id,
    authorized: resource.owner_id === user.id
  })
});
const result = await response.json();
if (!response.ok || result.decision !== "allow") {
  throw new Error("Access denied");
}`;

  return <section className="rounded-xl bg-cyber-panel border border-cyber-border p-5 shadow-tactical">
    <p className="font-mono text-xs text-cyber-cyan uppercase tracking-widest mb-2">Your organization</p>
    <h2 className="text-xl font-semibold text-white break-words">{user.tenant_name}</h2>
    <p className="text-sm text-slate-400 mt-1 break-all">{user.email}</p>
    <p className="text-xs text-slate-500 mt-3">Tenant ID <span className="font-mono text-slate-300">{user.tenant_id}</span></p>
    <div className="border-t border-cyber-border mt-4 pt-4">
      <h3 className="text-sm font-semibold text-slate-200">{eventCount ? 'Integration activity received' : 'Connect your backend'}</h3>
      <p className="text-xs text-slate-400 mt-2">{eventCount ? 'This dashboard shows only your tenant’s events. Activity refreshes automatically.' : 'Your dashboard is ready. Send authorization requests from your application to start seeing activity.'}</p>
      {usage && <p className="text-xs text-slate-300 mt-3">
        {usage.current_usage.requests_this_minute} / {usage.current_usage.requests_per_minute_limit} requests in the current window · {usage.current_usage.audit_events_stored} audit events
      </p>}
      <details className="mt-4">
        <summary className="cursor-pointer text-sm text-cyber-cyan">Server integration example</summary>
        <p className="text-xs text-slate-400 mt-3">Use your application's real authorization rules. Enforce the response before returning the resource. Keep the API key on your server.</p>
        <pre className="mt-3 p-3 bg-slate-950 rounded-lg overflow-x-auto text-[11px] text-slate-300">{snippet}</pre>
      </details>
    </div>
    {user.capabilities.manage_api_key && <div className="border-t border-cyber-border mt-4 pt-4">
      <h3 className="text-sm font-semibold text-slate-200">API key</h3>
      <p className="text-xs text-slate-400 mt-2">Your existing secret cannot be displayed again. Dashboard access does not require it.</p>
      {!replacing && !replacement && <button type="button" onClick={() => { setReplacing(true); setError(''); }} className="mt-3 text-sm text-cyber-cyan hover:underline">Replace a lost or compromised key</button>}
      {replacing && <form onSubmit={replace} className="mt-3 space-y-3">
        <p className="text-xs text-amber-300">Replacement immediately revokes the current key. Update your integration with the new key.</p>
        <label htmlFor="replace-password" className="block text-xs text-slate-300">Confirm your account password</label>
        <input id="replace-password" type="password" autoComplete="current-password" required value={password}
          onChange={e => setPassword(e.target.value)} className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm" />
        <div className="flex gap-3">
          <button type="submit" disabled={pending} className="rounded-lg bg-amber-400 text-slate-950 px-3 py-2 text-sm disabled:opacity-50">{pending ? 'Replacing...' : 'Revoke & replace key'}</button>
          <button type="button" disabled={pending} onClick={() => { setReplacing(false); setPassword(''); }} className="text-sm text-slate-400">Cancel</button>
        </div>
      </form>}
      {replacement && <div className="mt-3 space-y-3">
        <p className="text-xs text-amber-300">{replacement.warning}</p>
        <label htmlFor="replacement-key" className="block text-xs text-slate-300">New API key (shown once)</label>
        <input id="replacement-key" readOnly value={replacement.api_key} onFocus={e => e.target.select()}
          className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono" />
        <div className="flex gap-3">
          <button type="button" className="text-sm text-cyber-cyan" onClick={async () => {
            try { await navigator.clipboard.writeText(replacement.api_key); setCopied(true); }
            catch { setError('Select the key and copy it manually.'); }
          }}>{copied ? 'Copied' : 'Copy new key'}</button>
          <button type="button" onClick={() => { setReplacement(null); setCopied(false); }} className="text-sm text-slate-400">I've saved it</button>
        </div>
      </div>}
    </div>}
    {error && <p role="alert" className="text-sm text-rose-300 mt-3">{error}</p>}
  </section>;
}
