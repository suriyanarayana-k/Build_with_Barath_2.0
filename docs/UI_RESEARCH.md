# CyberAccess UI research and Stitch exploration

Research date: 10 October 2026. Platform baseline: v1.2.0.

## Purpose and evidence

Explore professional customer-facing UI directions before choosing an implementation. The audience is a developer integrating CyberAccess and the tenant owner investigating authorization activity. The first job is to connect a backend; the returning job is to understand a decision and act on evidence.

This research uses public vendor documentation and documented interface examples. It does not claim access to the vendors' private dashboards, measure their usability, or establish their security efficacy. The recommendations below are our application of the observed patterns to this project.

## Findings from primary sources

| Source | Documented interface pattern | Application to CyberAccess |
| --- | --- | --- |
| [Cloudflare Security Events](https://developers.cloudflare.com/waf/analytics/security-events/) | A time range and filters govern summaries and logs; expanding an event exposes context. Events are distinct from HTTP requests, and sampled logs have limitations. | Show scope above the data; connect a summary to its evidence; label audit events accurately and disclose the size of the loaded list. |
| [Cloudflare Security Overview](https://developers.cloudflare.com/security/overview/) | Security action items are prioritized and can be filtered by criticality and type. | Highlight an actionable denied/blocked subject rather than making every dashboard panel compete for attention. Avoid claiming a SOC incident-management workflow. |
| [Datadog AAP Security Signals](https://docs.datadoghq.com/security/application_security/threat_protection/security_signals/) | A searchable signal list opens a details panel; fields distinguish severity, entities and investigation state. Views can retain context. | Keep an event list beside its explanation, time, subject, resource and risk. Do not add assignment, incident creation or resolution controls because our backend has no such workflow. |
| [Stripe Workbench overview](https://docs.stripe.com/workbench/overview) | Integration activity, errors, keys and request/event inspection are accessible within a developer workspace. Time selection and list-to-detail navigation support debugging. | Keep API access and integration instructions one navigation step from activity. Show receipt of a first request as onboarding progress; provide a useful empty state. |
| [Stripe API keys](https://docs.stripe.com/keys) | Newly created live secret keys are displayed once; lost secrets need replacement. Key-management actions make the key lifecycle explicit. | Show the newly issued secret once, explain saving it, then use account login for dashboard access. Confirm replacement with the owner's password and explicitly disclose immediate revocation. |
| [Snyk Reports](https://docs.snyk.io/manage-risk/reporting/getting-started-with-snyk-reports) | Reports retain filters in their URLs; exported reports include their scope and context. | Plan bookmarkable time, subject and outcome filters. Keep tenant identity visible. Exports and saved server-side views are future work, not working prototype controls. |
| [Grafana dashboard best practices](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/) | Dashboards benefit from a clear purpose, appropriate visualizations and intentional organization. | Use a small summary followed by evidence. Every visual needs a real question, source and time window; avoid charts that exist only to fill space. |
| [W3C: Use of Color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html) | Color cannot be the only visual means of communicating information. | Combine decision labels and icons with color; provide legible focus states. Prototype appearance is not proof of WCAG compliance. |

## Recommended information architecture

Public entry points explain the product and offer Create account, Sign in, Documentation, and access for customers who already have a key. Account creation collects organization, email and password. The key-success step has Copy, an explicit saved-key acknowledgment and Open dashboard. The existing-key flow verifies ownership rather than guessing it from contact email.

Authenticated navigation is Overview, Activity, Subjects, API access, Usage and Documentation. Tenant identity and account controls stay visible. There is one tenant per owner account, so an organization-switching selector would imply a capability we do not provide.

The overview answers: Is my integration sending activity? What happened within the selected period? Which subject needs investigation? The activity view answers: Who accessed which resource, when, what was decided and why? API access answers: How do I connect, and how do I replace a lost credential?

## Layout rules for all options

- Use one primary action for the current job, persistent navigation, an obvious selected section and a clear tenant/time scope.
- Distinguish audit events, blocked events and currently blocked subjects. A minute quota is not a 24-hour activity total.
- Keep risk on the 0–100 scale, with the tenant's configured thresholds. Display detector contributions only when supplied by the backend.
- Display a truthful last-refresh label; retain prior data with a stale/error notice when refresh fails. Support retry without an endless spinner.
- First-use dashboards say Waiting for your first request and show a server integration example. Zero data is not a successful-protection claim.
- For small screens, collapse navigation, stack summaries, and show event details as a separate sheet. Keep touch actions at least 44px as a design target; verify actual contrast, focus and reflow during implementation.
- Use text/icons alongside status color. Reserve warning/error styling for actual states. Keep ordinary table text readable and IDs wrap-safe.
- Use no public demo reset/simulator controls in a customer console, no fabricated compliance seals, savings, latency, protection percentages or API inventory.
- Do not promise social login, email verification, MFA, recovery, invitations, multi-organization membership, billing or a multi-key lifecycle.

## Existing contracts and implementation boundaries

| UI area | Existing contract | Wiring detail |
| --- | --- | --- |
| Account creation / sign in / restore / sign out | `/auth/signup`, `/auth/login`, `/auth/session`, `/auth/logout` | Reuse HttpOnly session cookies and the existing console request header. Do not store keys or JWTs in localStorage. |
| Existing-key dashboard access | `/auth/claim-tenant` | Current key proves ownership; email/password establish the owner account. |
| New key / replacement | Signup response; `/auth/api-key/rotate` | Secret lives only in the success state. Replacement requires password and immediately revokes the previous key. No permanent Reveal action. |
| Overview and decision breakdown | `/tenants/{id}/analytics/overview?window_hours=...` | Returns total audit events, outcomes, average/max risk and blocked-subject count. Scope uses the authenticated tenant. |
| Recent activity and audit context | `/events`, `/audit-events`, `/audit-timeline` | A redesigned list can reuse readers. Complete server-side search, large-history pagination and persisted filter views need explicit backend work. Never present a limited loaded list as the complete history. |
| Subject investigation | `/risk/{subject}`, `/lockout-status/{subject}` | Use a subject ID from an event or search. Subjects is an investigation view, not a new account-management directory. |
| Threat summary | `/tenants/{id}/analytics/threat-summary` | Current data is IP event groups and flagged IPs. Do not fabricate geographical maps or counts of protected endpoints. |
| Usage | `/tenants/{id}/quota-usage` | Render current-window usage and limit separately from activity totals. |
| Connection progress | Authenticated account + receipt of an actual audit event | A checklist can derive progress locally. There is no persistent onboarding-step API or per-key last-used timestamp. |

The prototype may show filters and a time series as a proposed interaction. During wiring, derive bins from available timestamped events and clearly bound their coverage, or add a server aggregation/query contract. Do not render fabricated traffic after connecting the real backend. Do not equate API-key replacement audit entries with authorization attempts.

## Stitch directions

Each direction has a private Stitch project. The dashboard fixtures use Acme Commerce, the same KPI values and event rows, and a visible sample-data label. No customer data, real key or password is sent to Stitch. The user requested Stitch explicitly; it is the generation provider for this exploration.

| Option | Visual system | Layout and intended audience | Stitch project |
| --- | --- | --- | --- |
| A: Clear Workspace | Manrope, blue/ink, cool light surfaces, restrained 8px corners | Left navigation, overview summary, table and supporting details; general developer/tenant-owner audience | `6214059865088933773` |
| B: Analyst Console | IBM Plex Sans/Mono, amber/graphite, restrained dark surfaces | Horizontal navigation, compact summary and list/detail investigation workspace; frequent analyst use | `2975846223738962264` |
| C: Guided Workspace | DM Sans, teal/pine, warm ivory, softer 12px corners | Horizontal navigation, integration journey and task-led overview; simpler first-time onboarding | `16715378513620981607` |

A is the initial recommendation for a broadly usable customer console. B prioritizes investigation density. C prioritizes onboarding clarity. This recommendation is an inference; the user chooses the visual direction.

## Review and next step

Three dashboard concepts were generated and refined through Google Stitch MCP. The first dark screen had overlapping panels; the refined version fixes that layout. The review removed the invented burst limit, role label, privacy guarantee and secret fingerprint. Generated text still needs a contract review during implementation: filters, risk contributions and status descriptions must use actual returned fields; current blocked-subject counts do not establish which subjects generated all historical blocked events.

The screenshots are desktop concepts. A crops its lower inspector, B crops the rightmost account navigation, and C wraps some navigation labels. Implement natural page scrolling and responsive navigation when the user selects a direction. This is not a claim that those generated components pass responsive or accessibility testing.

| Direction | Refined Stitch screen |
| --- | --- |
| A | `projects/6214059865088933773/screens/1c9b5083b3ce4bc882aaa2e18295a256` |
| B | `projects/2975846223738962264/screens/99ff2bd9e4844d3ba9bfc10652dbb5d5` |
| C | `projects/16715378513620981607/screens/840b203d67554f399e9424a9f39ea920` |

The original prompts, full generation/refinement outputs, screenshots, HTML exports and review notes are preserved in `C:/Users/sanja/.gstack/projects/BUILD-WITH-BARATH-Build_with_Barath_2.0/designs/tenant-console-20261010-stitch/`. The self-contained comparison board is `design-board.html`; it includes large previews, optional ratings/comments and a saved selection. Provider output is labeled as unverified draft material rather than endorsing its production, performance or compliance claims.

The local board is available at [Compare the three Stitch directions](http://127.0.0.1:56378/boards/b-20261010-143157-pi09ie/). Browser checks confirmed three loaded full-resolution images, working large-preview/keyboard-close behavior, no horizontal overflow at 1440px and 390px, and no preselected choice. These checks cover the comparison board, not a production dashboard implementation.

## Approved implementation

The user selected **A: Clear Workspace** on 10 October 2026. Its light surfaces, Manrope typography, blue actions and left navigation now form the tenant console. [DESIGN.md](../DESIGN.md) records the tokens and interaction rules.

The six working destinations are Overview, Activity, Subjects, API access, Usage, and Documentation. Overview counts come from tenant analytics; the activity list and event inspector use recorded audit fields; subject investigation returns the current behavioral risk; quotas and thresholds use their backend endpoints. Time, query and decision filters persist in the URL. The list discloses its latest-100-event limit. Current block status, event outcomes and quota windows have separate labels. Empty data and refresh failures have explicit states.

Login, signup and existing-tenant claim screens share the approved theme. Dashboard access continues to use cookie sessions, while newly issued integration keys remain visible only in the issuing component. Replacement confirms the owner's password and explains immediate revocation. The existing demo workspace remains available only through its capability gate.

Implementation checks passed: 135 backend tests, 15 frontend tests, lint and production builds from both frontend entry points. Local Chromium checks covered all six destinations, signup/sign-in, session restoration, key replacement and sign-out; retained filters; real local authorization events; empty history; controlled refresh failures and recovery; and responsive layouts at 1440px, 768px, 390px and 375px. Mobile navigation also passed Escape, focus-wrap and background-inert checks. These checks are scoped to this change and are not a claim of complete WCAG or production certification.

QA used a disposable local SQLite database. Its real endpoint-generated test activity is separate from production tenant data. The backend API and Lost-found testing project were not changed for this UI implementation. Detailed evidence is stored in `.gstack/qa-reports/clear-workspace/` locally.
