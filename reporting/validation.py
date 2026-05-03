from __future__ import annotations

from typing import Any


def validate_findings(findings: list[dict[str, Any]], schema: dict[str, Any]) -> None:
    required = schema["required"]
    severity_values = set(schema["properties"]["severity"]["enum"])
    status_values = set(schema["properties"]["status"]["enum"])
    for index, finding in enumerate(findings):
        missing = [field for field in required if field not in finding]
        if missing:
            raise ValueError(f"Finding #{index} is missing required fields: {missing}")
        if finding["severity"] not in severity_values:
            raise ValueError(f"Finding #{index} has invalid severity: {finding['severity']}")
        if finding["status"] not in status_values:
            raise ValueError(f"Finding #{index} has invalid status: {finding['status']}")
        if not isinstance(finding["evidence"], list) or not all(isinstance(item, str) for item in finding["evidence"]):
            raise ValueError(f"Finding #{index} has invalid evidence structure")


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in findings:
        key = (item["host"], item["source"], item["category"], item["rule_id"])
        if key not in unique or (unique[key]["status"] != "fail" and item["status"] == "fail"):
            unique[key] = item
    return list(unique.values())
