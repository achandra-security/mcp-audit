import json
from pathlib import Path

import pytest

from mcp_audit import assess, load_inventory
from mcp_audit.checks import CHECKS
from mcp_audit.cli import main

CONFIGS = Path(__file__).resolve().parent.parent / "configs"

EXPECTED = {
    "hardened.json": [],
    "insecure_proxy.json": [
        "MCP-001", "MCP-001", "MCP-002", "MCP-003", "MCP-003", "MCP-004", "MCP-004", "MCP-005", "MCP-006",
        "MCP-007", "MCP-008", "MCP-009", "MCP-012", "MCP-012", "MCP-013", "MCP-013", "MCP-014", "MCP-014",
        "MCP-014", "MCP-015", "MCP-016",
    ],
    "poisoned_tools.json": ["MCP-010", "MCP-010", "MCP-011", "MCP-011"],
}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_sample_configs(name, expected):
    findings = assess(load_inventory(CONFIGS / name))
    assert sorted(f.check_id for f in findings) == expected


def test_every_finding_has_evidence_remediation_and_references():
    for name in EXPECTED:
        for f in assess(load_inventory(CONFIGS / name)):
            assert f.evidence and f.remediation and f.references
            assert f.severity in {"critical", "high", "medium", "low", "info"}


def test_check_ids_are_unique():
    ids = [c.check_id for c in CHECKS]
    assert len(ids) == len(set(ids)) == 16


def test_cli_text(capsys):
    assert main(["scan", str(CONFIGS / "poisoned_tools.json")]) == 0
    out = capsys.readouterr().out
    assert "[CRITICAL] MCP-010" in out and "MCP-011" in out


def test_cli_json_and_min_severity(capsys):
    main(["scan", str(CONFIGS / "insecure_proxy.json"), "--format", "json", "--min-severity", "critical"])
    data = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in data[0]["findings"]} == {"critical"}
    assert len(data[0]["findings"]) == 5


def test_cli_sarif_structure(capsys):
    main(["scan", str(CONFIGS / "insecure_proxy.json"), "--format", "sarif"])
    log = json.loads(capsys.readouterr().out)
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}
    assert len(run["results"]) == len(EXPECTED["insecure_proxy.json"])


def test_cli_fail_on(capsys):
    assert main(["scan", str(CONFIGS / "hardened.json"), "--fail-on", "info"]) == 0
    assert main(["scan", str(CONFIGS / "insecure_proxy.json"), "--fail-on", "critical"]) == 2
    capsys.readouterr()


def test_cli_rejects_unknown_check_and_bad_file(tmp_path, capsys):
    assert main(["scan", str(CONFIGS / "hardened.json"), "--only", "MCP-999"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert main(["scan", str(bad)]) == 1
    assert "invalid JSON" in capsys.readouterr().err


def test_cli_lists_checks(capsys):
    assert main(["checks"]) == 0
    assert capsys.readouterr().out.count("MCP-") == 16
