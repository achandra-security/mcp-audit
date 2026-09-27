"""Command-line interface.

    mcp-audit scan configs/insecure_proxy.json
    mcp-audit scan configs/*.json --format sarif > results.sarif
    mcp-audit scan inventory.json --fail-on high      # non-zero exit for CI gating
    mcp-audit checks
"""

from __future__ import annotations

import argparse
import sys

from .checks import CHECKS
from .engine import SEVERITY_ORDER, assess, filter_findings
from .model import ConfigError, load_inventory
from .report import to_json, to_sarif, to_text

SEVERITIES = list(SEVERITY_ORDER)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-audit", description="Offline security assessment of MCP server configurations.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="assess one or more inventory JSON files")
    scan.add_argument("paths", nargs="+")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--min-severity", choices=SEVERITIES, default="info")
    scan.add_argument("--only", action="append", default=[], metavar="CHECK_ID", help="run only these checks")
    scan.add_argument("--skip", action="append", default=[], metavar="CHECK_ID", help="skip these checks")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 if any finding is at or above this severity")
    sub.add_parser("checks", help="list available checks")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "checks":
        for c in sorted(CHECKS, key=lambda c: c.check_id):
            print(f"{c.check_id}  [{c.severity:<8}]  {c.title}")
        return 0

    known = {c.check_id for c in CHECKS}
    unknown = sorted((set(args.only) | set(args.skip)) - known)
    if unknown:
        print(f"mcp-audit: error: unknown check IDs {unknown}", file=sys.stderr)
        return 1

    results = []
    try:
        for path in args.paths:
            inventory = load_inventory(path)
            findings = assess(inventory, only=set(args.only) or None, skip=set(args.skip))
            results.append((path, filter_findings(findings, args.min_severity)))
    except (OSError, ConfigError) as exc:
        print(f"mcp-audit: error: {exc}", file=sys.stderr)
        return 1

    render = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format]
    print(render(results))

    if args.fail_on:
        floor = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= floor for _, fs in results for f in fs):
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
