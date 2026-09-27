"""Run registered checks over an inventory."""

from __future__ import annotations

from . import checks as _checks  # noqa: F401  (registers checks)
from .checks import CHECKS, Finding
from .model import Inventory

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def assess(inventory: Inventory, only: set[str] | None = None, skip: set[str] | None = None) -> list[Finding]:
    """Return findings sorted by severity (highest first), then check ID, server, and target."""
    selected = [c for c in CHECKS if (not only or c.check_id in only) and c.check_id not in (skip or set())]
    findings: list[Finding] = []
    for chk in selected:
        if chk.scope == "inventory":
            findings.extend(chk.run(inventory))
        else:
            for server in inventory.servers:
                findings.extend(chk.run(server))
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check_id, f.server, f.target, f.evidence))


def filter_findings(findings: list[Finding], min_severity: str) -> list[Finding]:
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]
