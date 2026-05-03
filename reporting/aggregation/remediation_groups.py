from __future__ import annotations

import pathlib
import re
from typing import Any

import yaml

from reporting.aggregation.severity import calculate_priority
from reporting.common import severity_rank, stable_id, unique_sorted


DEFAULT_TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "config" / "remediation_templates.yaml"


def _templates() -> dict[str, Any]:
    if not DEFAULT_TEMPLATES.exists():
        return {}
    return yaml.safe_load(DEFAULT_TEMPLATES.read_text(encoding="utf-8")) or {}


def remediation_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    if finding.get("type") == "software_vulnerability":
        package = finding.get("package", {})
        return ("package_update", package.get("name"), package.get("fixed_condition"))
    if finding.get("type") == "configuration_noncompliance":
        requirement = finding.get("requirement", {})
        return ("config_change", finding.get("subsystem", "other"), requirement.get("id"))
    return ("manual_review", finding.get("type", "unknown"))


def _extract_mountpoint(finding: dict[str, Any]) -> str:
    text = " ".join([finding.get("title", ""), finding.get("check", {}).get("command", ""), finding.get("check", {}).get("expected", "")])
    match = re.search(r"(/(?:tmp|var|home|dev/shm)\b)", text)
    return match.group(1) if match else "/tmp"


def _extract_module(finding: dict[str, Any]) -> str:
    text = " ".join([finding.get("title", ""), finding.get("check", {}).get("command", "")])
    match = re.search(r"\b(cramfs|freevxfs|hfs|hfsplus|jffs2|squashfs|udf|usb-storage)\b", text, re.I)
    return match.group(1) if match else "<module>"


def _verification_for_config(finding: dict[str, Any]) -> list[str]:
    templates = _templates()
    subsystem = finding.get("subsystem")
    if subsystem == "filesystem":
        return [item.format(mountpoint=_extract_mountpoint(finding)) for item in templates.get("mount_options", {}).get("verification", [])]
    if subsystem == "audit":
        return templates.get("audit", {}).get("verification", [])
    if subsystem == "logging":
        return templates.get("logging", {}).get("verification", [])
    if subsystem == "kernel":
        return [item.format(module=_extract_module(finding)) for item in templates.get("kernel", {}).get("verification", [])]
    command = finding.get("check", {}).get("command")
    return [command] if command and command != "not provided" else ["repeat Wazuh SCA scan"]


def _package_commands(findings: list[dict[str, Any]]) -> tuple[list[str], list[str], str]:
    templates = _templates().get("package_update", {})
    packages = unique_sorted([item.get("package", {}).get("name") for item in findings])
    package_text = " ".join(packages) or "<package>"
    pattern = "|".join(re.escape(package) for package in packages) or "<package>"
    commands = [item.format(packages=package_text, package_pattern=pattern) for item in templates.get("commands", [])]
    verification = [item.format(packages=package_text, package_pattern=pattern) for item in templates.get("verification", [])]
    return commands, verification, templates.get("rollback", "restore from backup or snapshot if required")


def build_remediation_groups(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by remediation action."""
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for finding in findings:
        buckets.setdefault(remediation_key(finding), []).append(finding)

    groups: list[dict[str, Any]] = []
    for key, items in buckets.items():
        action_type = key[0]
        affected_assets = unique_sorted([asset for item in items for asset in item.get("affected_assets", [])])
        severity_max = max((item.get("severity", {}).get("level", "info") for item in items), key=severity_rank, default="info")
        if action_type == "package_update":
            package_name = key[1] or "packages"
            commands, verification, rollback = _package_commands(items)
            title = f"Update {package_name} packages"
            summary = f"Update {package_name} packages to versions satisfying scanner conditions"
            group_id = stable_id("REM-PKG", package_name, key[2])
        elif action_type == "config_change":
            sample = items[0]
            title = sample.get("title") or f"Fix {key[1]} configuration"
            summary = sample.get("remediation", {}).get("summary", "Apply required configuration change")
            commands = sample.get("remediation", {}).get("commands", [])
            verification = _verification_for_config(sample)
            rollback = "Restore previous configuration file or system snapshot if change causes regression"
            group_id = stable_id("REM-CFG", key[1], key[2])
        else:
            title = "Manual review"
            summary = "Review findings manually"
            commands = []
            verification = ["repeat Wazuh scan"]
            rollback = "not provided"
            group_id = stable_id("REM-MANUAL", *key)

        group = {
            "group_id": group_id,
            "action_type": action_type,
            "title": title,
            "severity_max": severity_max,
            "affected_assets": affected_assets,
            "affected_findings": [item["finding_uid"] for item in items],
            "summary": summary,
            "commands": commands,
            "verification": verification,
            "rollback": rollback,
        }
        group["priority"] = calculate_priority({**group, "severity": {"level": severity_max, "score": 0}})
        groups.append(group)

    return sorted(groups, key=lambda item: (item["priority"], -severity_rank(item["severity_max"]), -len(item["affected_assets"]), item["title"]))
