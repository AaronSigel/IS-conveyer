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


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("title", ""),
        finding.get("subsystem", ""),
        finding.get("check", {}).get("command", ""),
        finding.get("check", {}).get("expected", ""),
        finding.get("description", ""),
        finding.get("impact", ""),
        finding.get("remediation", {}).get("summary", ""),
    ]
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        parts.extend(str(item) for item in evidence)
    return " ".join(str(part or "") for part in parts).lower()


def _package_family(package_name: str) -> str:
    name = package_name.lower()
    if name in {"openssl", "libssl3", "libssl-dev", "libcrypto3"} or name.startswith("libssl"):
        return "openssl"
    if name.startswith("linux-image") or name.startswith("linux-modules") or name.startswith("linux-headers") or name in {"linux-generic", "linux-base"}:
        return "ubuntu-kernel"
    return name or "packages"


def _config_action_key(finding: dict[str, Any]) -> str:
    text = _finding_text(finding)
    title = str(finding.get("title") or "").lower()
    subsystem = str(finding.get("subsystem") or "other")

    if "aide" in text:
        return "aide"
    if "core dump" in text or "coredump" in text or "systemd-coredump" in text:
        return "core_dumps"
    if "sshd" in text or "ssh " in text or " ssh" in text:
        return "ssh"
    if "pam" in text or "faillock" in text or "pwquality" in text or "password" in text:
        return "pam"
    if "audit" in text or "auditd" in text or "augenrules" in text or "auditctl" in text:
        if "50-scope.rules" in text or "scope" in title:
            return "audit_50_scope"
        if "50-user_emulation.rules" in text or "user emulation" in title:
            return "audit_50_user_emulation"
        if "50-identity.rules" in text or "identity" in title:
            return "audit_50_identity"
        if "99-finalize.rules" in text or "immutable" in text or "finalize" in title:
            return "audit_99_finalize"
        return "auditd"
    if "/tmp" in text or "/dev/shm" in text:
        return "tmp_mount_options"
    if "/var/log/audit" in text or "/var/log" in text or "/var/tmp" in text or re.search(r"\b/var\b", text):
        return "system_partitions"
    if subsystem == "filesystem" and any(option in text for option in ("nodev", "nosuid", "noexec", "partition", "mount")):
        return "filesystem_mount_options"
    if subsystem == "kernel":
        return f"kernel_module:{_extract_module(finding)}"
    if subsystem == "logging":
        return "logging"
    return f"{subsystem}:{finding.get('requirement', {}).get('id') or finding.get('title')}"


def remediation_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    if finding.get("type") == "software_vulnerability":
        package = finding.get("package", {})
        package_name = str(package.get("name") or "")
        return ("package_update", _package_family(package_name), package.get("fixed_condition"))
    if finding.get("type") == "configuration_noncompliance":
        return ("config_change", _config_action_key(finding))
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
    action_key = _config_action_key(finding)
    if action_key in templates:
        return templates.get(action_key, {}).get("verification", [])
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


def _commands_for_config(finding: dict[str, Any]) -> list[str]:
    template = _templates().get(_config_action_key(finding), {})
    return template.get("commands", []) or finding.get("remediation", {}).get("commands", [])


def _rollback_for_config(finding: dict[str, Any]) -> str:
    template = _templates().get(_config_action_key(finding), {})
    return template.get("rollback") or "Restore previous configuration file or system snapshot if change causes regression"


def _config_title_summary(action_key: str, findings: list[dict[str, Any]]) -> tuple[str, str]:
    template = _templates().get(action_key, {})
    if template.get("title") or template.get("summary"):
        return template.get("title") or findings[0].get("title"), template.get("summary") or findings[0].get("remediation", {}).get("summary", "")
    titles = {
        "aide": "Configure AIDE integrity monitoring",
        "core_dumps": "Disable and harden core dump handling",
        "ssh": "Harden sshd_config",
        "pam": "Configure PAM password and lockout policy",
        "auditd": "Configure auditd and audit rules",
        "audit_50_scope": "Configure audit scope rules",
        "audit_50_user_emulation": "Configure audit user emulation rules",
        "audit_50_identity": "Configure audit identity rules",
        "audit_99_finalize": "Finalize audit rules",
        "tmp_mount_options": "Harden temporary filesystems",
        "system_partitions": "Separate and harden system log/data partitions",
        "filesystem_mount_options": "Harden filesystem mount options",
        "logging": "Configure system logging",
    }
    title = titles.get(action_key, findings[0].get("title") or "Apply configuration change")
    summary = f"Apply {len(findings)} related configuration checks as one operational change"
    return title, summary


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
            title, summary = _config_title_summary(str(key[1]), items)
            commands = _commands_for_config(sample)
            verification = _verification_for_config(sample)
            rollback = _rollback_for_config(sample)
            group_id = stable_id("REM-CFG", key[1])
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
