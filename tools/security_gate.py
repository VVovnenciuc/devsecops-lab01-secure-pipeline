#!/usr/bin/env python3
"""Security gate: agregă rapoarte SARIF și decide pass/fail pe baza unei politici.

Toate scanerele rulează în mod „raportează, nu bloca”; gate-ul e SINGURUL punct de decizie.
Exit codes: 0 = pass, 1 = findings blocante, 2 = eroare (raport lipsă/invalid → fail closed).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

EXIT_PASS = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "none"}

logger = logging.getLogger("security_gate")


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    path: str
    line: int
    message: str


@dataclass(frozen=True)
class Waiver:
    rule_id: str
    reason: str
    expires: dt.date
    path: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.rule_id != finding.rule_id:
            return False
        return self.path is None or finding.path.startswith(self.path)


@dataclass(frozen=True)
class Policy:
    fail_on: str = "high"
    tool_severity: dict[str, str] = field(default_factory=dict)
    waivers: list[Waiver] = field(default_factory=list)


class GateError(Exception):
    """Input invalid: gate-ul pică (fail closed)."""


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    # 1) scor CVSS numeric (Trivy, CodeQL etc.), 2) fallback pe nivelul SARIF
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        score = props.get("security-severity")
        if score is not None:
            try:
                return severity_from_score(float(score))
            except (TypeError, ValueError):
                logger.warning("invalid security-severity %r", score)
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return LEVEL_TO_SEVERITY.get(str(level or "warning"), "medium")


def parse_sarif(path: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read SARIF {path}: {exc}") from exc
    if not isinstance(data, dict) or "runs" not in data:
        raise GateError(f"{path} is not a SARIF document")

    findings: list[Finding] = []
    for run in data["runs"] or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = str(driver.get("name") or path.stem)
        rules = {str(r.get("id")): r for r in driver.get("rules") or []}
        for result in run.get("results") or []:
            if result.get("suppressions"):
                continue  # suprimat explicit în cod (ex. # nosemgrep) → auditat separat
            rule_id = str(result.get("ruleId") or "unknown")
            location = ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=_severity(result, rules.get(rule_id, {})),
                    path=str((location.get("artifactLocation") or {}).get("uri", "")),
                    line=int((location.get("region") or {}).get("startLine") or 0),
                    message=str((result.get("message") or {}).get("text", ""))[:200],
                )
            )
    return findings


def load_policy(path: Path) -> Policy:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"cannot read policy {path}: {exc}") from exc

    fail_on = str(raw.get("fail_on", "high")).lower()
    tool_severity = {
        str(k).lower(): str(v).lower() for k, v in (raw.get("tool_severity") or {}).items()
    }
    for value in [fail_on, *tool_severity.values()]:
        if value not in SEVERITY_RANK:
            raise GateError(f"invalid severity in policy: {value}")

    waivers: list[Waiver] = []
    for item in raw.get("waivers") or []:
        expires = item.get("expires")
        if not item.get("rule_id") or not item.get("reason") or not isinstance(expires, dt.date):
            raise GateError(f"waiver {item!r} needs rule_id, reason and expires (date)")
        waivers.append(
            Waiver(
                rule_id=str(item["rule_id"]),
                reason=str(item["reason"]),
                expires=expires,
                path=item.get("path"),
            )
        )
    return Policy(fail_on=fail_on, tool_severity=tool_severity, waivers=waivers)


def evaluate(
    findings: list[Finding], policy: Policy, today: dt.date
) -> tuple[list[Finding], list[Finding]]:
    threshold = SEVERITY_RANK[policy.fail_on]
    active: list[Waiver] = []
    for waiver in policy.waivers:
        if waiver.expires < today:
            logger.warning("waiver %s expired on %s, ignored", waiver.rule_id, waiver.expires)
        else:
            active.append(waiver)

    blocking: list[Finding] = []
    waived: list[Finding] = []
    for finding in findings:
        override = policy.tool_severity.get(finding.tool.lower())
        current = replace(finding, severity=override) if override else finding
        if SEVERITY_RANK[current.severity] < threshold:
            continue
        if any(w.matches(current) for w in active):
            waived.append(current)
        else:
            blocking.append(current)
    return blocking, waived


def render_markdown(
    blocking: list[Finding], waived: list[Finding], total: int, policy: Policy
) -> str:
    lines = [
        "## 🛡️ Security gate",
        "",
        f"Prag: **{policy.fail_on}** · findings analizate: {total} · "
        f"blocante: **{len(blocking)}** · cu excepție (waiver): {len(waived)}",
        "",
    ]
    if blocking:
        lines += ["| Severitate | Tool | Regulă | Locație |", "|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: -SEVERITY_RANK[x.severity]):
            lines.append(f"| {f.severity} | {f.tool} | `{f.rule_id}` | `{f.path}:{f.line}` |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("GATE_LOG_LEVEL", "INFO"),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    parser = argparse.ArgumentParser(prog="security_gate", description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(".security-gate.toml"))
    parser.add_argument("reports", nargs="+", type=Path, help="rapoarte SARIF")
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy)
        findings = [f for report in args.reports for f in parse_sarif(report)]
    except GateError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR

    blocking, waived = evaluate(findings, policy, dt.date.today())
    summary = render_markdown(blocking, waived, len(findings), policy)
    print(summary)

    if os.environ.get("GITHUB_ACTIONS") == "true":
        for f in blocking:  # adnotări vizibile direct în diff-ul PR-ului
            print(f"::error file={f.path},line={f.line},title={f.tool} {f.rule_id}::{f.severity}")
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)

    if blocking:
        logger.error("%d blocking finding(s) at or above '%s'", len(blocking), policy.fail_on)
        return EXIT_BLOCKED
    logger.info("gate passed")
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
