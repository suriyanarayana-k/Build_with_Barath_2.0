import { useEffect, type ReactNode } from 'react';
import { CircleCheck, ListFilter, KeyRound } from 'lucide-react';
import BrandMark from './BrandMark';

export default function AuthFrame({ children, title }: { children: ReactNode; title: string }) {
  useEffect(() => { document.title = `${title} | CyberAccess`; }, [title]);
  return <div className="cc-auth">
    <aside className="cc-auth-story">
      <a href="/login" className="cc-brand"><BrandMark />CyberAccess</a>
      <div>
        <p className="cc-eyebrow">YOUR SECURITY WORKSPACE</p>
        <h2>Clear decisions.<br />Useful evidence.</h2>
        <p>Connect your backend, understand behavioral risk, and investigate your own tenant’s activity.</p>
        <ul>
          <li><CircleCheck size={20} />A private dashboard for your organization</li>
          <li><ListFilter size={20} />Audit activity with recorded explanations</li>
          <li><KeyRound size={20} />A server API key, issued once</li>
        </ul>
      </div>
      <p className="cc-muted">Your backend checks ownership. CyberAccess adds behavioral checks.</p>
    </aside>
    <div className="cc-auth-form">{children}</div>
  </div>;
}
