from __future__ import annotations

import pathlib
import re
from functools import lru_cache
from typing import Any

import yaml


DEFAULT_RULES = pathlib.Path(__file__).resolve().parents[1] / "config" / "applicability_rules.yaml"
EXCEPTION_STATUSES = {"not_applicable", "accepted_risk", "manual_review", "environment_specific"}


@lru_cache(maxsize=4)
def load_applicability_rules(path: str | None = None) -> list[dict[str, Any]]:
    rules_path = pathlib.Path(path) if path else DEFAULT_RULES
    if not rules_path.exists():
        return []
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules") if isinstance(data, dict) else []
    return [rule for rule in rules if isinstance(rule, dict)]


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("finding_uid", ""),
        finding.get("title", ""),
        finding.get("subsystem", ""),
        finding.get("description", ""),
        finding.get("impact", ""),
        finding.get("check", {}).get("command", ""),
        finding.get("check", {}).get("expected", ""),
        finding.get("remediation", {}).get("summary", ""),
    ]
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        parts.extend(str(item) for item in evidence)
    refs = finding.get("references")
    if isinstance(refs, dict):
        for value in refs.values():
            if isinstance(value, list):
                parts.extend(str(item) for item in value)
    return " ".join(str(part or "") for part in parts).lower()


def _matches_any(patterns: Any, value: str) -> bool:
    if not isinstance(patterns, list):
        return False
    return any(re.search(str(pattern).lower(), value, re.I) for pattern in patterns if str(pattern or "").strip())


def _rule_matches(rule: dict[str, Any], finding: dict[str, Any]) -> bool:
    text = _finding_text(finding)
    title = str(finding.get("title") or "").lower()
    requirement = str(finding.get("requirement", {}).get("id") or "").lower()

    ids = rule.get("requirement_ids")
    if isinstance(ids, list) and requirement in {str(item).lower() for item in ids}:
        return True
    if _matches_any(rule.get("title_patterns"), title):
        return True
    if _matches_any(rule.get("text_patterns"), text):
        return True
    return False


def _applicability_record(status: str, *, rule: dict[str, Any] | None = None) -> dict[str, Any]:
    rule = rule or {}
    if status not in EXCEPTION_STATUSES:
        return {
            "status": "applicable",
            "include_in_remediation_plan": True,
            "reason": "",
            "rule_id": "",
            "notes": "",
        }
    return {
        "status": status,
        "include_in_remediation_plan": False,
        "reason": str(rule.get("reason") or ""),
        "rule_id": str(rule.get("id") or ""),
        "notes": str(rule.get("notes") or ""),
    }


def apply_applicability(findings: list[dict[str, Any]], policy_options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Attach applicability metadata to findings.

    Profile options may provide explicit ``applicability_overrides`` by
    finding UID or requirement id. Config rules cover common CIS checks whose
    remediation depends on local architecture or accepted risk decisions.
    """
    overrides = (policy_options or {}).get("applicability_overrides")
    overrides = overrides if isinstance(overrides, dict) else {}
    rules = load_applicability_rules()

    for finding in findings:
        override = overrides.get(finding.get("finding_uid")) or overrides.get(finding.get("requirement", {}).get("id"))
        if isinstance(override, str):
            finding["applicability"] = _applicability_record(override)
            continue
        if isinstance(override, dict):
            status = str(override.get("status") or "applicable")
            finding["applicability"] = _applicability_record(status, rule=override)
            continue
        matched = next((rule for rule in rules if _rule_matches(rule, finding)), None)
        finding["applicability"] = _applicability_record(str(matched.get("status")) if matched else "applicable", rule=matched)
    return findings


def is_in_remediation_scope(finding: dict[str, Any]) -> bool:
    applicability = finding.get("applicability")
    if not isinstance(applicability, dict):
        return True
    return bool(applicability.get("include_in_remediation_plan", True))
