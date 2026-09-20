# NetScope

**An authorised, defensive network exposure scanner.**

It probes hosts you own, works out what is listening, and reports the exposure
with the evidence behind every conclusion.

> **Authorisation.** Only scan systems and networks you own or have explicit
> written permission to test. Scanning third-party infrastructure without
> authorisation is unlawful in many jurisdictions. The scanner refuses public
> addresses by default and every scan request must carry an explicit
> authorisation flag.

---

## What it does

| Stage | What happens |
| --- | --- |
| Target validation | IPv4 address, CIDR range or hostname, parsed into `ipaddress` objects |
| Host discovery | Ranges get a fast liveness sweep before the full port list |
| Port scanning | TCP connect scan; optional, conservative UDP probing |
| Service detection | Plugin detectors per protocol, plus a generic banner reader |
| Fingerprinting | HTTP headers and titles, SSH/FTP/SMTP/MySQL banners, TLS certificates |
| Vulnerability lookup | OSV and NVD, behind one provider interface |
| Misconfiguration checks | TLS problems, cleartext HTTP, missing headers, anonymous FTP, admin interfaces |
| Risk scoring | A transparent 0–100 score you can trace back to individual findings |
| Storage | SQLite, so history and trends survive a restart |

It does **not** exploit anything. There is no brute forcing, no credential
spraying, no directory enumeration, no evasion, and no persistence. Where an
honest answer would need credentials, it says a human should check.

---

## Architecture

```
frontend/  React + TypeScript + Vite + Tailwind, TanStack Query, Recharts
    │  REST + Server-Sent Events
    ▼
backend/   FastAPI
    ├── api/          route handlers only
    ├── schemas/      Pydantic request/response models
    ├── models/       SQLAlchemy tables
    └── services/
        ├── scanner/          engines: SocketScanner, NmapScanner
        ├── fingerprinting/   one detector per protocol
        ├── vulnerability/    OSV + NVD behind VulnerabilityProvider
        ├── misconfiguration/ non-destructive checks
        ├── pipeline.py       the stage machine
        ├── risk.py           scoring
        └── scan_manager.py   background tasks, progress fan-out
```

Scanner logic never imports from `api/`. The pipeline talks only to the
`Scanner` interface, so the socket engine can be replaced with Nmap — or later
a raw SYN engine — without touching callers.

---

## Installation

Requires **Python 3.13+** and **Node 20+**.

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### Running the backend

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Interactive API docs: <http://127.0.0.1:8000/docs>

### Running the frontend

```bash
cd frontend
npm run dev                      # http://localhost:5173
```

The dev server proxies `/api` to `http://127.0.0.1:8000`, so no CORS setup is
needed locally. Override with `VITE_API_PROXY`.

### Installing Nmap (optional)

The socket engine is the default and needs nothing beyond the standard
library. For richer service/version detection:

```bash
# Install system Nmap first: https://nmap.org/download
pip install -r backend/requirements-optional.txt
```

`/api/health` reports which engines are available. If Nmap is missing, the
application silently falls back to the socket engine — it never breaks.

### Database

SQLite, created automatically on first start at `backend/network_scanner.db`.
No migrations to run. Point `NES_DATABASE_URL` elsewhere to change it.

---

## Running a scan

**From the UI:** open <http://localhost:5173>, go to *New scan*, enter a
target, tick the authorisation box, and start. Progress streams live.

**From the CLI:**

```bash
cd backend
python -m scanner_cli scan 192.168.1.10 --ports 22,80,443
```

```
Network Exposure Scanner

Target: 192.168.1.10
Engine: socket

192.168.1.10
  22/tcp     OPEN          OpenSSH 9.6
  80/tcp     OPEN          nginx 1.24.0
  443/tcp    OPEN          nginx 1.24.0

  Findings:
    [MEDIUM  ] Unencrypted HTTP service on port 80
    [LOW     ] Missing HTTP security headers on port 443

  Risk score: 31.2 (medium)
```

Options: `--profile quick|standard|custom`, `--ports`, `--timeout`,
`--concurrency`, `--udp`, `--engine`, `--json`, `--quiet`.

The CLI exits `1` when anything high or critical was found, so it can gate a
pipeline; `2` on a validation error.

**From the API:**

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.1.0/24","profile":"quick","authorized":true}'
```

---

## API

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/scans` | Start a scan (returns immediately) |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Full scan detail with hosts and findings |
| DELETE | `/api/scans/{id}` | Delete a scan and its results |
| POST | `/api/scans/{id}/cancel` | Request cancellation |
| GET | `/api/scans/{id}/hosts` | Hosts for one scan |
| GET | `/api/scans/{id}/topology` | Discovered scanner → host → port graph |
| GET | `/api/scans/{id}/stream` | SSE live progress |
| GET | `/api/hosts/{id}` | Host detail |
| GET | `/api/hosts/{id}/ports` | Ports on a host |
| GET | `/api/hosts/{id}/findings` | Findings on a host |
| GET | `/api/findings` | Filter by severity, type, host, CVE, text |
| GET | `/api/findings/{id}` | One finding |
| GET | `/api/dashboard/summary` | Aggregate counts and leaderboards |
| GET | `/api/dashboard/trends` | Per-scan history for the charts |
| GET | `/api/health` | Liveness, engine availability, active scans |

Errors share one envelope:

```json
{ "error": { "message": "…", "status": 422, "detail": [ … ] } }
```

---

## How findings are judged

Every finding carries **severity, reason, evidence, confidence and a
recommendation**. The reason states why that severity was assigned; nothing is
asserted without saying what it is based on.

Confidence is not decoration:

| Confidence | Meaning |
| --- | --- |
| `confirmed` | Observed directly on this host, or matched by NVD's own CPE version ranges |
| `probable` | A real version-range match from OSV against the detected version |
| `possible` | A lead to verify — typically a keyword match, never proof |

**A product family having had CVEs is not evidence that your deployment is
vulnerable.** When only a keyword search matched, the scanner refuses to
assert individual CVEs against the host. It emits one informational finding
listing the candidates as leads, rather than a wall of red that cannot be
justified.

### Risk score

A bounded 0–100 figure: severity weights discounted by confidence, then passed
through a saturating curve so the number cannot be inflated by piling up
low-severity noise. `INFO` findings contribute nothing. The scan detail view
lists the findings that produced the score.

---

## Demo environment

```bash
docker compose up --build
```

Brings up the API (`:8000`), the UI (`:5173`), and two ordinary target
services — nginx and Redis — on an isolated `172.28.0.0/24` bridge. Scan that
range from the UI to exercise discovery, fingerprinting and the sensitive
service checks.

The demo targets are stock images in default configuration. Nothing is
deliberately made vulnerable.

---

## Testing

```bash
make test                        # everything
cd backend  && python -m pytest  # 159 tests
cd frontend && npm run test      # 29 tests
```

Tests never touch an external host. The backend spins up local listeners on
ephemeral ports; vulnerability providers are stubbed; the frontend mocks the
API module entirely.

Two areas get deliberately thorough coverage, because both fail quietly:

- **Cancellation** is exercised end to end — a scan is started, cancelled
  mid-flight, and asserted to stop and land in a terminal state in the
  database. A cancel button that only stops the UI updating is worse than none.
- **Certificate parsing** runs against real certificates built in memory
  (valid, expired, self-signed, CA-signed, wildcard), because the failure mode
  here is returning nothing rather than raising.

---

## Security posture of the tool itself

- Targets are parsed into `ipaddress` objects and hostnames are matched
  against an anchored RFC 1123 pattern — nothing shell-like survives parsing.
- Port specifications accept only digits, commas and hyphens.
- The Nmap engine receives argument lists, never a shell string. No
  `shell=True` anywhere in the codebase.
- Public targets are refused unless explicitly enabled server-side.
- Concurrency is capped, every probe is rate-limited through a token bucket,
  and every network call has a timeout.
- No credentials are stored, requested, or transmitted.
- The UI cannot cause arbitrary commands to run on the host.

---

## Limitations

- **IPv4 only.** IPv6 targets are rejected rather than silently mishandled.
- **TCP connect, not SYN.** Needs no privileges and is honest in target logs,
  but it is slower and more visible than a raw SYN scan.
- **UDP is inferential.** Silence is reported as `open|filtered`, never as a
  confirmed service. Only seven common ports are probed by default.
- **Version detection depends on banners.** A service that hides or spoofs its
  version will not be fingerprinted accurately.
- **Vulnerability mapping is partial.** Version-aware matching only covers
  products in the curated OSV and CPE maps; everything else degrades to a
  keyword lead. This is deliberate — a wrong mapping produces confident
  nonsense.
- **Single-process task manager.** Four concurrent scans, and running scans do
  not survive an API restart.
- **No authentication on the API.** It is built to run on localhost. Do not
  expose it to a network you do not control.

## Future improvements

- A raw SYN engine behind the existing `Scanner` interface
- IPv6 support end to end
- Proper CPE matching from banner text, to widen confirmed version matches
- Scheduled recurring scans with diffing between runs
- Export to CSV, JSON and SARIF for CI pipelines
- Authentication and multi-user scan ownership
