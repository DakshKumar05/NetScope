# Architecture notes

## The pipeline

`app/services/pipeline.py` is a stage machine. Each stage reports progress
through a callback and checks a cancellation event, so a stopped scan actually
stops rather than running to completion invisibly.

```
validate -> discover -> port scan -> fingerprint -> vuln lookup
         -> misconfiguration checks -> risk -> persist
```

Discovery is skipped for a single host. For a range it runs a small liveness
sweep first, so the full port list is not spent on addresses nobody is using.

## Why the scanner is an interface

`Scanner` exposes `scan_host` and `scan_network`. Two implementations exist:

- `SocketScanner` — asyncio TCP connect plus conservative UDP. Requires no
  privileges. The default.
- `NmapScanner` — used only when system Nmap and `python-nmap` are both
  present. Arguments are built as a list; no shell string is ever constructed
  from a target.

A raw SYN engine would be a third implementation and would require no changes
anywhere else.

## Why UDP is treated differently

A UDP probe that gets no answer means "open or filtered". It is not evidence
of a service. The scanner records `open|filtered` and the UI says so plainly.
Only an ICMP port-unreachable — surfacing as a connection error — reliably
means closed.

The probe payloads are ordinary protocol questions: a DNS root-zone query, an
NTP client request, an SNMP `sysDescr` read, an SSDP discovery. None is
malformed, and none is chosen for amplification.

## Why TLS is inspected twice

Python returns an empty dict from `getpeercert()` when verification is
disabled. The certificates most worth reporting — expired and self-signed ones
— are by definition the ones that fail verification, so a single unverified
handshake would yield no certificate data at all.

The detector therefore handshakes once with verification on, to learn whether
the chain is trusted, and once with it off to take the certificate in DER form
and parse it with `cryptography`. No downgrade, no cipher forcing, no bypass
beyond reading what the server already presents to every client.

## Confidence, and why keyword hits are demoted

Three levels: `confirmed`, `probable`, `possible`.

`VulnerabilityService` stops at the first provider returning a version-aware
match, so a genuine range match is never diluted by a text search. If only
keyword results came back, it emits **one informational finding** naming the
candidates as leads, rather than asserting each CVE against the host.

The alternative — listing every CVE a product family has ever had — produces a
page of red that cannot be justified from the evidence, and teaches the reader
to ignore the tool.

## Risk scoring

```
points = sum(severity_weight * confidence_factor)
score  = 100 * (1 - e^(-points / 60))
```

Saturating, so the score stays inside 0-100 however many findings arrive, and
cannot be inflated by piling up low-severity noise. `INFO` weighs zero. The
top contributors are returned alongside the score so the number is auditable.

## Background scans

`ScanManager` owns the asyncio tasks. Scans run outside the request that
started them, so the HTTP call returns immediately and the work survives the
client disconnecting. Progress is fanned out to SSE subscribers through
per-subscriber queues; a subscriber that cannot keep up is dropped rather than
allowed to stall the scan. Persistence runs on a worker thread because the
SQLAlchemy session is synchronous.

Four concurrent scans, enforced by a semaphore. No Celery and no Redis — the
tool does not run at a scale that would justify either.

## The security boundary

`app/core/targets.py` is the only place where user input becomes something the
scanner acts on. Targets become `ipaddress` objects; hostnames must match an
anchored RFC 1123 pattern; port specifications accept only digits, commas and
hyphens. Everything downstream receives typed values, so no injection payload
has a path to a subprocess.

The public-address guard is separate and deliberate: `NES_ALLOW_PUBLIC_TARGETS`
defaults to false, and the API additionally requires an explicit `authorized`
flag on every scan request. Neither alone is sufficient.
