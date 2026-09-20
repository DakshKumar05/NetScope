"""Command-line entry point.

    python -m scanner_cli scan 192.168.1.10 --ports 22,80,443

Runs the same pipeline the API uses, so CLI and dashboard results agree.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.core.enums import Severity
from app.core.targets import TargetValidationError
from app.services.pipeline import ScanCancelled, ScanOutcome, ScanPipeline, ScanRequest

BANNER = "Network Exposure Scanner"

SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scanner_cli",
        description=(
            "Authorised network exposure scanner. Only scan systems you own or "
            "have explicit permission to test."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a host, hostname or CIDR range")
    scan.add_argument("target", help="192.168.1.10 | 192.168.1.0/24 | nas.local")
    scan.add_argument("--ports", help="22,80,443 or 1-1024")
    scan.add_argument(
        "--profile",
        choices=("quick", "standard", "custom"),
        default="quick",
        help="Port set to use when --ports is omitted (default: quick)",
    )
    scan.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout")
    scan.add_argument("--concurrency", type=int, default=100, help="Parallel probes")
    scan.add_argument("--udp", action="store_true", help="Also probe common UDP ports")
    scan.add_argument(
        "--engine", choices=("auto", "socket", "nmap"), default="auto", help="Scan engine"
    )
    scan.add_argument("--json", action="store_true", help="Emit JSON instead of a report")
    scan.add_argument("--quiet", action="store_true", help="Suppress progress output")
    return parser


def render_text(outcome: ScanOutcome) -> str:
    lines = [f"\n{BANNER}\n", f"Target: {outcome.target.raw}"]
    lines.append(f"Engine: {outcome.engine}")
    lines.append("")

    if not outcome.hosts:
        lines.append("No responsive hosts were found.")
        return "\n".join(lines)

    for host in outcome.hosts:
        label = f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "")
        lines.append(label)
        if not host.ports:
            lines.append("  no open ports")
            lines.append("")
            continue

        for port_finding in host.ports:
            port = port_finding.port
            service = port_finding.service
            descriptor = service.product or service.name or "unknown"
            if service.version:
                descriptor += f" {service.version}"
            endpoint = f"{port.port}/{port.protocol}"
            lines.append(f"  {endpoint:<10} {port.state.upper():<13} {descriptor}")

        findings = sorted(
            host.findings,
            key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.title),
        )
        actionable = [f for f in findings if f.severity != Severity.INFO]
        if actionable:
            lines.append("")
            lines.append("  Findings:")
            for finding in actionable:
                lines.append(f"    [{finding.severity.upper():<8}] {finding.title}")
        if host.risk:
            lines.append(f"\n  Risk score: {host.risk.score} ({host.risk.level})")
        lines.append("")

    counts = outcome.risk.counts
    summary = ", ".join(f"{count} {level}" for level, count in counts.items()) or "none"
    lines.append(f"Overall risk: {outcome.risk.score} ({outcome.risk.level})")
    lines.append(f"Findings: {summary}")
    return "\n".join(lines)


def render_json(outcome: ScanOutcome) -> str:
    payload = {
        "target": outcome.target.raw,
        "engine": outcome.engine,
        "risk": outcome.risk.as_dict(),
        "hosts": [
            {
                "ip": host.ip,
                "hostname": host.hostname,
                "status": host.status,
                "risk": host.risk.as_dict() if host.risk else None,
                "ports": [
                    {
                        "port": pf.port.port,
                        "protocol": pf.port.protocol,
                        "state": pf.port.state,
                        "latency_ms": pf.port.latency_ms,
                        "service": {
                            "name": pf.service.name,
                            "product": pf.service.product,
                            "version": pf.service.version,
                            "banner": pf.service.banner,
                            "confidence": pf.service.confidence,
                        },
                        "findings": [
                            {
                                "type": f.type,
                                "severity": f.severity,
                                "title": f.title,
                                "reason": f.reason,
                                "evidence": f.evidence,
                                "recommendation": f.recommendation,
                                "confidence": f.confidence,
                                "cve_id": f.cve_id,
                                "cvss": f.cvss,
                                "references": f.references,
                            }
                            for f in pf.findings
                        ],
                    }
                    for pf in host.ports
                ],
            }
            for host in outcome.hosts
        ],
    }
    return json.dumps(payload, indent=2)


async def run_scan(args: argparse.Namespace) -> int:
    async def progress(phase: str, value: float, message: str) -> None:
        if args.quiet or args.json:
            return
        print(f"  [{phase:<22}] {value * 100:5.1f}%  {message}", file=sys.stderr)

    request = ScanRequest(
        target=args.target,
        profile="custom" if args.ports else args.profile,
        ports=args.ports,
        udp=args.udp,
        timeout=args.timeout,
        concurrency=args.concurrency,
        engine=args.engine,
    )

    pipeline = ScanPipeline(request, on_progress=None if args.json else progress)
    try:
        outcome = await pipeline.run()
    except TargetValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ScanCancelled:
        print("Scan cancelled.", file=sys.stderr)
        return 130
    finally:
        await pipeline.close()

    print(render_json(outcome) if args.json else render_text(outcome))

    # Non-zero when something actionable was found, so CI can gate on it.
    worst = max(
        (SEVERITY_RANK.get(f.severity, 0) for f in outcome.findings),
        default=0,
    )
    return 1 if worst >= SEVERITY_RANK[Severity.HIGH] else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
