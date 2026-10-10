---
# gstack: design-md-format=spec
name: CyberAccess Clear Workspace
description: A light tenant console that connects authorization decisions to their evidence.
colors:
  primary: "#245bdb"
  on-primary: "#ffffff"
  primary-hover: "#1b49b8"
  surface: "#ffffff"
  canvas: "#f6f8fc"
  text: "#17233d"
  text-muted: "#5b6b82"
  border: "#dfe5ee"
  selected: "#eaf0ff"
  success: "#087047"
  success-surface: "#ecfdf5"
  warning: "#986000"
  warning-surface: "#fffbeb"
  error: "#b42334"
  error-surface: "#fff0f2"
typography:
  display:
    fontFamily: Manrope
    fontWeight: 700
    fontSize: 1.75rem
    letterSpacing: -0.02em
  body:
    fontFamily: Manrope
    fontSize: 0.875rem
    lineHeight: 1.5
  label:
    fontFamily: Manrope
    fontSize: 0.75rem
    letterSpacing: 0.02em
  mono:
    fontFamily: JetBrains Mono
    fontFeature: tnum
rounded:
  sm: 5px
  md: 6px
  lg: 8px
  auth-panel: 10px
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  2xl: 48px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.md}"
    minHeight: 44px
  input:
    borderColor: "#cdd6e5"
    rounded: "{rounded.md}"
    minHeight: 44px
  card:
    backgroundColor: "{colors.surface}"
    borderColor: "{colors.border}"
    rounded: "{rounded.lg}"
  nav-link:
    textColor: "#516076"
    minHeight: 44px
---

# CyberAccess Clear Workspace

## Overview

The user selected Stitch direction A on 10 October 2026. This design serves developers connecting a backend and tenant owners investigating decisions. The console is an Operate surface; integration documentation is a Read surface. Research and primary-source links are in [docs/UI_RESEARCH.md](docs/UI_RESEARCH.md).

Use a visible tenant identity, restrained summaries, and a list beside its evidence. The implemented React components reuse the existing cookie-session and tenant-scoped API contracts.

## Colors

Blue identifies navigation and actions. Neutral surfaces separate content without competing with decisions. Decision colors always accompany an icon and a label. A subject's current block status must not imply that an authorization request was allowed.

## Typography

Manrope is the approved UI face; JetBrains Mono distinguishes identifiers and code. System fonts remain usable while web fonts load. Explanatory paragraphs use Pretext after fonts are ready to estimate their minimum height; native wrapping remains available. Event tables use a denser scale than explanatory content.

## Layout

The desktop sidebar remains visible beside a bounded, fluid workspace. Summary cards use four columns, then two. Supporting panels stack on tablets. At the phone breakpoint, navigation becomes a modal drawer; tables and code examples scroll inside their containers. The refresh timestamp can wrap below its controls.

## Elevation & Depth

Borders and surface tints carry the hierarchy. Cards use a very light shadow. Avoid decorative glow, gradients and dashboard panels added merely to fill space.

## Shapes

Cards have restrained corners; controls and badges use smaller radii. Authentication panels follow the same surface hierarchy with a slightly softer outer corner.

## Components

The approved brand icon is B, the CA monogram. Its source files are `bola-frontend/public/brand/cyberaccess-mark.svg` (blue mark) and `cyberaccess-app-icon.svg` (white mark in the blue tile), mirrored in the root public directory. PNG exports provide a 512px app icon and a 180px Apple touch icon, rendered from that SVG. Use the shared BrandMark component beside the CyberAccess wordmark; demo tools use the same app icon. Browser tabs use the app icon and a page-specific title ending in `| CyberAccess`; the HTML fallback is `CyberAccess | API Security`. The browser theme color uses the primary brand color.

The six console destinations are Overview, Activity, Subjects, API access, Usage, and Documentation. Public sign-in, signup and existing-tenant claim screens share the same visual system. Capability-gated demo tools retain their existing interface.

Focus must remain visible. Mobile navigation traps focus, closes with Escape, restores focus on dismissal and makes the background inert. Disabled controls disclose pending work. Refresh failures retain previous values with an explicit stale-data notice and retry action.

## Do's and Don'ts

- Use API counts and recorded decisions. Show a missing score as unavailable, and leave average risk unavailable when there are no events.
- Distinguish selected-period events, current block status, current-minute quotas, and all-time storage.
- Disclose that activity filters cover the latest 100 loaded events; retain filters in the URL.
- Store newly issued keys only in the current component state; explain immediate revocation before replacement.
- Do not invent detector percentages, traffic trends, incidents, roles or compliance guarantees.
- Do not send integration keys from a customer's browser; examples use server environment variables and explicit ownership checks.

## Motion

Only pending refresh work uses a rotating indicator. Respect reduced-motion preferences. No decorative entrance animation is required.

## Decisions Log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-10-10 | Implement approved direction A in the existing React frontend | The user chose Clear Workspace after reviewing the Stitch examples. |
| 2026-10-10 | Use an outcome breakdown instead of a fabricated traffic chart | The current API exposes counts and a bounded event list, not complete time-series bins. |
| 2026-10-10 | Separate the tenant console from capability-gated demo tools | Customer navigation should expose tenant activity and integration controls directly. |
| 2026-10-10 | Use icon B, the CA monogram, for navigation and the browser tab | The user selected B from the six generated icon directions and requested a title-bar update. |
