"""Text, JSON, and SARIF 2.1.0 renderers."""

from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .checks import CHECKS, Finding
from .engine import SEVERITY_ORDER

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def to_text(results: list[tuple[str, list[Finding]]]) -> str:
    lines = ["mcp-audit assessment report", "=" * 27]
    for source, findings in results:
        counts = Counter(f.severity for f in findings)
        summary = ", ".join(f"{s}={counts[s]}" for s in sorted(counts, key=lambda s: -SEVERITY_ORDER[s]))
        lines += ["", f"{source}: {len(findings)} finding(s)" + (f" ({summary})" if findings else "")]
        for f in findings:
            lines += [
                "",
                f"  [{f.severity.upper()}] {f.check_id} {f.title}",
                f"    server:      {f.server}",
                f"    target:      {f.target}",
                f"    evidence:    {f.evidence}",
                f"    remediation: {f.remediation}",
                f"    references:  {'; '.join(f.references)}",
            ]
    return "\n".join(lines)


def to_json(results: list[tuple[str, list[Finding]]]) -> str:
    return json.dumps(
        [{"source": source, "findings": [f.to_dict() for f in findings]} for source, findings in results],
        indent=2,
    )


def to_sarif(results: list[tuple[str, list[Finding]]]) -> str:
    """SARIF 2.1.0 log, suitable for GitHub code scanning upload."""
    rules = [
        {
            "id": c.check_id,
            "name": c.func.__name__,
            "shortDescription": {"text": c.title},
            "help": {"text": c.remediation},
            "properties": {
                "tags": ["security", "mcp"],
                "security-severity": SECURITY_SEVERITY[c.severity],
            },
        }
        for c in sorted(CHECKS, key=lambda c: c.check_id)
    ]
    sarif_results = []
    for source, findings in results:
        for f in findings:
            sarif_results.append(
                {
                    "ruleId": f.check_id,
                    "level": SARIF_LEVEL[f.severity],
                    "message": {"text": f"[{f.server}] {f.target}: {f.evidence}. {f.remediation}"},
                    "locations": [
                        {
                            "physicalLocation": {"artifactLocation": {"uri": source}},
                            "logicalLocations": [{"name": f.target, "fullyQualifiedName": f"{f.server}/{f.target}"}],
                        }
                    ],
                    "properties": {"severity": f.severity, "security-severity": SECURITY_SEVERITY[f.severity]},
                }
            )
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/achandra-security/mcp-audit",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(log, indent=2)
