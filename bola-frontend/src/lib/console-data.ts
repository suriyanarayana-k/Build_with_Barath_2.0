import type { AuditEvent } from './api';

export const VIEWS = ['overview', 'activity', 'subjects', 'api-access', 'usage', 'documentation'] as const;
export type ConsoleView = typeof VIEWS[number];
export function readConsoleView(path = window.location.pathname): ConsoleView {
  const segment = path.split('/')[2];
  return VIEWS.includes(segment as ConsoleView) ? segment as ConsoleView : 'overview';
}
export function visibleEvents(events: AuditEvent[], hours: number, now: number, query = '', outcome = '') {
  const needle = query.trim().toLowerCase();
  return events.filter(event => event.occurred_at >= now - hours * 3600 &&
    (!outcome || event.outcome === outcome) &&
    (!needle || [event.subject_id, event.record_id, event.explanation].some(value => String(value ?? '').toLowerCase().includes(needle))));
}
export function decisionLabel(value: string) {
  return ({ allowed: 'Allowed', denied: 'Denied', blocked: 'Blocked' } as Record<string, string>)[value] || value || 'Unknown';
}
export function riskText(value?: number) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(value % 1 ? 1 : 0) : '—';
}
