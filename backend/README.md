# Backend — Network Exposure Scanner API

FastAPI service that runs scans, stores results in SQLite, and streams
progress over Server-Sent Events.

## Run

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Docs at <http://127.0.0.1:8000/docs>. Configuration is documented in
`.env.example`; every variable is optional.

## Layout

```
app/
  main.py                    app wiring, CORS, one error envelope
  config.py                  settings (NES_* environment variables)
  core/
    targets.py               target + port parsing - the security boundary
    enums.py                 severities, states, phases
    findings.py              FindingDraft
    ratelimit.py             token bucket
  api/                       routes, dependencies, serializers
  models/                    Scan, Host, Port, Service, Finding
  schemas/                   Pydantic models
  services/
    scanner/                 Scanner interface + socket and nmap engines
    fingerprinting/          detector plugins + registry
    vulnerability/           VulnerabilityProvider, OSV, NVD, cache
    misconfiguration/        non-destructive checks
    pipeline.py              the stage machine
    risk.py                  scoring
    scan_manager.py          background tasks, cancellation, SSE fan-out
scanner_cli/                 python -m scanner_cli
tests/                       pytest suite
```

## Adding a service detector

```python
from app.services.fingerprinting.base import ServiceDetector, ServiceInfo, read_banner


class RedisDetector(ServiceDetector):
    name = "redis"
    ports = (6379,)

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        banner = await read_banner(host, port, timeout=2.0)
        if not banner:
            return None
        ...
```

Then call `registry.register(RedisDetector())`. It is inserted ahead of the
generic fallback, which claims every port.

## Adding a vulnerability provider

Implement `VulnerabilityProvider.lookup(product, version)` and pass it to
`VulnerabilityService(providers=[...])`. Return `Confidence.POSSIBLE` unless
you genuinely matched a version range — the service refuses to raise
possible-only results into per-CVE findings.

## Tests

```bash
python -m pytest
```

No test contacts an external host: local listeners are started on ephemeral
ports and the vulnerability providers are stubbed.
