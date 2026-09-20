# Frontend — Network Exposure Scanner

React + TypeScript + Vite. Tailwind v4 for styling, TanStack Query for server
state, Recharts for charts, React Router for navigation.

## Run

```bash
npm install
npm run dev        # http://localhost:5173
```

`/api` is proxied to `http://127.0.0.1:8000` in development, so no CORS
configuration is needed. Override with `VITE_API_PROXY`. For a deployed build,
set `VITE_API_BASE` to the API origin.

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Dev server with HMR |
| `npm run build` | Type-check and production build |
| `npm run preview` | Serve the production build |
| `npm run test` | Component tests (Vitest + Testing Library) |

## Layout

```
src/
  components/    ui.tsx (primitives), charts.tsx, FindingDrawer, ScanProgress, Topology
  pages/         Dashboard, NewScan, Scans, ScanDetail, HostDetail, Findings
  layouts/       AppLayout (sidebar shell)
  hooks/         useScanStream (SSE), useToast, useTheme
  services/      api.ts - every API call, one axios client
  types/         mirrors the backend schemas
  test/          Vitest setup, factories, page tests
```

## Two design decisions worth knowing

**Severity is never carried by colour alone.** Every severity mark ships with
an icon and its name. The reserved red/amber/yellow status hues sit too close
together to be told apart as adjacent stacked bands — measured, not guessed —
so severity-over-time is faceted into one small single-hue panel per level
rather than stacked into one chart.

**Trends are single-series.** Hosts, open ports and risk each get their own
panel. There is no dual-axis chart anywhere: two y-scales on one plot invite
false correlation, and there is no honest shared scale between a host count
and a 0-100 score.
