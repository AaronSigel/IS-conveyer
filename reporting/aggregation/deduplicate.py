from __future__ import annotations

import copy
from typing import Any

from reporting.common import stable_id, unique_sorted


def package_dedup_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    package = finding.get("package", {})
    asset = next(iter(finding.get("affected_assets", []) or ["unknown"]))
    agent_id = finding.get("asset_details", {}).get(asset, {}).get("agent.id") or asset
    return (
        agent_id,
        finding.get("cve"),
        package.get("name"),
        package.get("installed_version"),
        package.get("architecture"),
    )


def configuration_dedup_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    requirement = finding.get("requirement", {})
    check = finding.get("check", {})
    return (requirement.get("id"), check.get("command"), check.get("expected"))


def dedup_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    if finding.get("type") == "software_vulnerability":
        return ("pkg", *package_dedup_key(finding))
    if finding.get("type") == "configuration_noncompliance":
        return ("cfg", *configuration_dedup_key(finding))
    return ("other", finding.get("finding_uid"))


def _merge_dict(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key not in target or target[key] in (None, "", {}, []):
            target[key] = copy.deepcopy(value)


def merge_findings(base: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    merged["affected_assets"] = unique_sorted(list(merged.get("affected_assets", [])) + list(item.get("affected_assets", [])))
    merged.setdefault("raw_refs", []).extend(item.get("raw_refs", []))
    merged["evidence"] = unique_sorted(list(merged.get("evidence", [])) + list(item.get("evidence", [])))
    merged["under_evaluation"] = bool(merged.get("under_evaluation") or item.get("under_evaluation"))
    _merge_dict(merged.setdefault("asset_details", {}), item.get("asset_details", {}))

    if merged.get("type") == "software_vulnerability":
        package = merged.setdefault("package", {})
        package.setdefault("installed_versions", {})
        package["installed_versions"].update(item.get("package", {}).get("installed_versions", {}))
    return merged


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge duplicate findings and aggregate affected assets."""
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        key = dedup_key(finding)
        if key in unique:
            unique[key] = merge_findings(unique[key], finding)
        else:
            unique[key] = copy.deepcopy(finding)
    for finding in unique.values():
        if not finding.get("finding_uid"):
            finding["finding_uid"] = stable_id("FND", *dedup_key(finding))
    return list(unique.values())
