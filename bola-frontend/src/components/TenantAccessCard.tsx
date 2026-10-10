import { useState, type FormEvent } from 'react';
import { KeyRound, Copy, Check, ArrowRight } from 'lucide-react';
import { API_BASE, replaceApiKey, type DashboardUser, type SignupResult } from '../lib/api';

export default function TenantAccessCard({ user }: { user: DashboardUser; eventCount?: number }) {
  const [error, setError] = useState('');
  const [replacing, setReplacing] = useState(false);
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [replacement, setReplacement] = useState<SignupResult | null>(null);
  const [copied, setCopied] = useState(false);
  const base = API_BASE.startsWith('http') ? API_BASE : window.location.origin + API_BASE;
  const replace = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setPending(true);
    try { setReplacement(await replaceApiKey(password)); setReplacing(false); }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not replace the key.'); }
    finally { setPassword(''); setPending(false); }
  };
  return <section className="cc-card cc-access">
    <div className="cc-card-heading"><h2>Server API key</h2><KeyRound size={20} aria-hidden="true" /></div>
    <p className="cc-muted">The existing secret cannot be displayed again. Sign in with your account to return to this dashboard.</p>
    <dl className="cc-fields"><div><dt>Organization</dt><dd>{user.tenant_name}</dd></div><div><dt>Tenant ID</dt><dd>{user.tenant_id}</dd></div><div><dt>Authorization endpoint</dt><dd>{base}/v1/authorize</dd></div></dl>
    <p className="cc-muted">Keep the key in your backend’s secret storage. Send it using the X-API-Key header.</p>
    {user.capabilities.manage_api_key ? <div className="cc-separated">
      {!replacing && !replacement && <><h3>Need a new key?</h3><p className="cc-muted">Replace a lost or compromised credential. The previous key will stop working immediately.</p><button className="cc-button cc-secondary" onClick={() => { setReplacing(true); setError(''); }}>Replace API key <ArrowRight size={16} /></button></>}
      {replacing && <form onSubmit={replace}>
        <p className="cc-warning">Replacement immediately revokes your current key. Update your server with the new secret before sending more requests.</p>
        <label htmlFor="replace-password">Confirm your account password</label>
        <input id="replace-password" className="cc-input" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
        <div className="cc-key-actions"><button className="cc-button" disabled={pending}>{pending ? 'Replacing…' : 'Revoke & replace key'}</button><button type="button" className="cc-button cc-secondary" disabled={pending} onClick={() => { setReplacing(false); setPassword(''); setError(''); }}>Cancel</button></div>
      </form>}
      {replacement && <div>
        <p className="cc-warning">{replacement.warning}</p><label htmlFor="replacement-key">New API key · shown once</label>
        <input id="replacement-key" className="cc-input" readOnly value={replacement.api_key} onFocus={e => e.target.select()} />
        <div className="cc-key-actions"><button className="cc-button" onClick={async () => { try { await navigator.clipboard.writeText(replacement.api_key); setCopied(true); } catch { setError('Copy is unavailable. Select the key and copy it manually.'); } }}>{copied ? <Check size={16} /> : <Copy size={16} />}{copied ? 'Copied' : 'Copy new key'}</button><button className="cc-button cc-secondary" onClick={() => { setReplacement(null); setCopied(false); setError(''); }}>I’ve saved it</button></div>
        <p className="cc-muted">Leaving this screen also hides the new secret.</p>
      </div>}
    </div> : <p className="cc-muted">This account cannot replace the integration key.</p>}
    {error && <p role="alert" className="cc-error">{error}</p>}
  </section>;
}
