import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

import security_gate as gate

TODAY = dt.date(2026, 10, 15)


def finding(severity: str, tool: str = "Semgrep", rule_id: str = "r1") -> gate.Finding:
    return gate.Finding(tool, rule_id, severity, "src/app.py", 3, "msg")


def sarif(tmp_path: Path, tool: str, results: list[dict[str, Any]], rules: Any = None) -> Path:
    doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": rules or []}}, "results": results}],
    }
    path = tmp_path / f"{tool}.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def result(rule_id: str, level: str = "warning", **extra: Any) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": "x"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
        **extra,
    }


def test_cvss_score_wins_over_level(tmp_path: Path) -> None:
    rules = [{"id": "CVE-1", "properties": {"security-severity": "9.8"}}]
    findings = gate.parse_sarif(sarif(tmp_path, "Trivy", [result("CVE-1", "note")], rules))
    assert findings[0].severity == "critical"


def test_suppressed_results_are_skipped(tmp_path: Path) -> None:
    res = result("r1", "error", suppressions=[{"kind": "inSource"}])
    assert gate.parse_sarif(sarif(tmp_path, "Semgrep", [res])) == []


def test_threshold_blocks_high_ignores_medium() -> None:
    blocking, _ = gate.evaluate([finding("high"), finding("medium")], gate.Policy(), TODAY)
    assert [f.severity for f in blocking] == ["high"]


def test_tool_severity_override() -> None:
    policy = gate.Policy(tool_severity={"gitleaks": "critical"})
    blocking, _ = gate.evaluate([finding("medium", tool="gitleaks")], policy, TODAY)
    assert blocking[0].severity == "critical"


@pytest.mark.parametrize(
    ("expires", "blocked"),
    [(dt.date(2026, 12, 1), 0), (dt.date(2026, 1, 1), 1)],
)
def test_waiver_active_vs_expired(expires: dt.date, blocked: int) -> None:
    policy = gate.Policy(waivers=[gate.Waiver("r1", "reason", expires)])
    blocking, _ = gate.evaluate([finding("high")], policy, TODAY)
    assert len(blocking) == blocked


def test_main_fails_closed_on_missing_report(tmp_path: Path) -> None:
    policy = tmp_path / "p.toml"
    policy.write_text('fail_on = "high"\n', encoding="utf-8")
    assert gate.main(["--policy", str(policy), str(tmp_path / "missing.sarif")]) == gate.EXIT_ERROR


def test_main_blocks_and_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    policy = tmp_path / "p.toml"
    policy.write_text('fail_on = "high"\n', encoding="utf-8")
    bad = sarif(tmp_path, "Bandit", [result("B602", "error")])
    assert gate.main(["--policy", str(policy), str(bad)]) == gate.EXIT_BLOCKED
    ok = sarif(tmp_path, "Hadolint", [result("DL3008", "note")])
    assert gate.main(["--policy", str(policy), str(ok)]) == gate.EXIT_PASS


def test_invalid_waiver_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "p.toml"
    policy.write_text('[[waivers]]\nrule_id = "x"\n', encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_policy(policy)
