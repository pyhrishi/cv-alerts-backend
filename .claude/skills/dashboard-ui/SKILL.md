# Skill: Dashboard UI Conventions

## When to use
Building any frontend screen or component for the alerts dashboard.

## Audience-first design
Primary user = an **OT SOC analyst / plant security engineer** monitoring an industrial
network. They need to triage fast: what's wrong, how bad, which asset, what to do. Optimize
for scannability and trust, not flashiness. Secondary audience = the Cisco interview panel,
so polish and clarity of intent count.

## Page structure
- **Top KPI strip**: active alerts by severity, assets monitored, silent devices, last refresh time.
- **Alerts page (core deliverable)**: filterable/sortable list of the three alert types.
  Each row: severity chip, title, affected asset(s), detected time, status. Click → detail panel
  with evidence, rationale, compliance ref, recommended action.
- **Communication graph (required)**: Cytoscape.js node-edge view of asset-to-asset flows.
  Color nodes by zone/type; highlight nodes involved in an active alert; let a selected alert
  focus/zoom its assets in the graph. This is where "visualize communicational relations" lives.
- **Trends (nice-to-have)**: Recharts alert volume over time / severity distribution.

## Visual system
- Use a calm, high-contrast OT-ops palette (dark or neutral surface, reserved accent colors).
- Severity colors must be consistent everywhere: critical=red, high=orange, medium=amber,
  low=blue, info=grey. Define once as tokens.
- Tailwind utility classes; extract repeated patterns into components (SeverityChip, AlertRow,
  KpiCard, GraphCanvas).
- Empty/loading/error states are mandatory — a security tool that silently shows nothing is worse
  than useless. Show "no active alerts" and "couldn't reach backend" states explicitly.

## Data flow
- Frontend calls OUR backend only (`NEXT_PUBLIC_API_BASE_URL`). Never the CV center.
- Poll the backend on an interval (e.g. 15–30s) and show a live "last updated" timestamp.
- Type every API response with a shared TypeScript interface mirroring the backend Pydantic model.

## Before building components
Read `/mnt/skills/public/frontend-design/SKILL.md` if available for design-token guidance, and
keep the look intentional rather than default-Bootstrap-ish.
