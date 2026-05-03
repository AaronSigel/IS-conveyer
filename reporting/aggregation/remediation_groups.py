from __future__ import annotations

import pathlib
import re
from collections import Counter
from typing import Any

import yaml

from reporting.aggregation.severity import calculate_priority
from reporting.common import severity_rank, stable_id, unique_sorted


DEFAULT_TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "config" / "remediation_templates.yaml"
DEFAULT_RULES = pathlib.Path(__file__).resolve().parents[1] / "config" / "remediation_rules.yaml"


def _templates() -> dict[str, Any]:
    templates = yaml.safe_load(DEFAULT_TEMPLATES.read_text(encoding="utf-8")) if DEFAULT_TEMPLATES.exists() else {}
    templates = templates or {}
    if DEFAULT_RULES.exists():
        data = yaml.safe_load(DEFAULT_RULES.read_text(encoding="utf-8")) or {}
        for rule in data.get("rules", []) or []:
            if not isinstance(rule, dict):
                continue
            action_key = rule.get("action_key") or rule.get("id")
            if not action_key:
                continue
            templates[str(action_key)] = {
                **templates.get(str(action_key), {}),
                "title": rule.get("group") or rule.get("title"),
                "summary": rule.get("summary"),
                "commands": rule.get("commands", []),
                "verification": rule.get("verification", []),
                "rollback": rule.get("rollback"),
                "priority_hint": rule.get("priority_hint"),
            }
    return templates


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
    if "apparmor" in text:
        return "apparmor"
    if "pam" in text or "faillock" in text or "pwquality" in text or "password" in text:
        return "pam"
    if "chrony" in text or "ntp" in text or "time synchronization" in text or "timesync" in text:
        return "time_sync"
    if "cron" in text or re.search(r"\bat\b", text):
        return "cron_at"
    if "ufw" in text or "iptables" in text or "ip6tables" in text or "nftables" in text or "firewall" in text:
        return "firewall"
    if "message of the day" in text or "motd" in text or "login banner" in text or "/etc/issue" in text:
        return "login_banners"
    if "telnet" in text or "rsh" in text or "nis" in text or "talk client" in text or "ldap-utils" in text:
        return "insecure_services"
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
        return "kernel_modules"
    if subsystem == "logging":
        return "logging"
    return f"{subsystem}:{finding.get('requirement', {}).get('id') or finding.get('title')}"


VALID_FIREWALL_BACKENDS = {"nftables", "ufw", "iptables", "none"}


def _firewall_backend_from_text(text: str) -> str | None:
    if "ufw" in text or "uncomplicated firewall" in text:
        return "ufw"
    if "nftables" in text or re.search(r"\bnft\b", text):
        return "nftables"
    if "iptables" in text or "ip6tables" in text:
        return "iptables"
    return None


def _selected_firewall_backend(policy_options: dict[str, Any] | None) -> str:
    backend = str((policy_options or {}).get("firewall_backend") or "").strip().lower()
    return backend if backend in VALID_FIREWALL_BACKENDS else ""


def _firewall_finding_applies(finding: dict[str, Any], backend: str) -> bool:
    if backend == "none":
        return False
    text = _finding_text(finding)
    finding_backend = _firewall_backend_from_text(text)
    return finding_backend in (None, backend)


def remediation_key(finding: dict[str, Any], policy_options: dict[str, Any] | None = None) -> tuple[Any, ...] | None:
    if finding.get("type") == "software_vulnerability":
        package = finding.get("package", {})
        asset = next(iter(finding.get("affected_assets", []) or ["unknown"]))
        agent_id = finding.get("asset_details", {}).get(asset, {}).get("agent.id") or asset
        return (
            "package_update",
            agent_id,
            asset,
            package.get("name"),
            package.get("installed_version"),
            package.get("architecture"),
        )
    if finding.get("type") == "configuration_noncompliance":
        action_key = _config_action_key(finding)
        if action_key == "firewall":
            backend = _selected_firewall_backend(policy_options)
            if not backend:
                return ("config_change", "firewall:choose")
            if not _firewall_finding_applies(finding, backend):
                return None
            return ("config_change", f"firewall:{backend}")
        return ("config_change", action_key)
    return ("manual_review", finding.get("type", "unknown"))


def _extract_mountpoint(finding: dict[str, Any]) -> str:
    text = " ".join([finding.get("title", ""), finding.get("check", {}).get("command", ""), finding.get("check", {}).get("expected", "")])
    match = re.search(r"(/(?:tmp|var|home|dev/shm)\b)", text)
    return match.group(1) if match else "/tmp"


def _extract_module(finding: dict[str, Any]) -> str | None:
    text = " ".join(
        [
            finding.get("title", ""),
            finding.get("check", {}).get("command", ""),
            finding.get("check", {}).get("expected", ""),
            finding.get("description", ""),
            finding.get("remediation", {}).get("summary", ""),
        ]
    )
    match = re.search(
        r"\b(cramfs|freevxfs|hfs|hfsplus|jffs2|squashfs|udf|usb-storage|dccp|tipc|rds|sctp|afs|ceph|cifs|nfs|nfsv3|nfsv4|gfs2|vfat|bluetooth|firewire-core)\b",
        text,
        re.I,
    )
    return match.group(1).lower() if match else None


def _verification_step(
    command: str,
    *,
    expected_result: str = "Command completes successfully and confirms the desired state",
    requires_root: bool = False,
    safe_to_run: bool = True,
    manual: bool = False,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "command": command,
        "expected_result": expected_result,
        "requires_root": requires_root,
        "safe_to_run": safe_to_run,
        "manual": manual,
        "notes": notes,
    }


def _normalize_verification(items: list[Any], *, expected_result: str = "Command output matches the remediation target") -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            command = str(item.get("command") or "").strip()
            if not command or command == "unknown" or "<module>" in command:
                continue
            steps.append(
                _verification_step(
                    command,
                    expected_result=str(item.get("expected_result") or expected_result),
                    requires_root=bool(item.get("requires_root", False)),
                    safe_to_run=bool(item.get("safe_to_run", True)),
                    manual=bool(item.get("manual", False)),
                    notes=str(item.get("notes") or ""),
                )
            )
            continue
        command = str(item or "").strip()
        if not command or command == "unknown" or "<module>" in command:
            continue
        requires_root = bool(re.search(r"\b(auditctl|augenrules|apparmor_status|ufw|iptables|ip6tables|nft|sysctl|sshd)\b", command))
        steps.append(_verification_step(command, expected_result=expected_result, requires_root=requires_root))
    return steps


def _verification_for_config_group(action_key: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    templates = _templates()
    steps = _normalize_verification(_template_for_action(action_key).get("verification", []))
    if steps:
        return steps
    subsystem = findings[0].get("subsystem")
    if action_key == "kernel_modules":
        modules = unique_sorted([module for module in (_extract_module(item) for item in findings) if module])
        return [
            _verification_step(
                f"modprobe -n -v {module}",
                expected_result=f"Module {module} is configured as install /bin/false or is not loadable",
                safe_to_run=True,
            )
            for module in modules
        ] + [
            _verification_step(
                "lsmod | grep -E '" + "|".join(re.escape(module) for module in modules) + "' || true",
                expected_result="No listed disabled modules are currently loaded",
                safe_to_run=True,
            )
        ] if modules else [_verification_step("repeat Wazuh SCA scan", expected_result="Kernel module checks pass", manual=True, notes="No concrete module name was present in affected findings")]
    if subsystem == "filesystem":
        mountpoints = unique_sorted([_extract_mountpoint(item) for item in findings])
        return _normalize_verification(
            [
                command.format(mountpoint=mountpoint)
                for mountpoint in mountpoints
                for command in templates.get("mount_options", {}).get("verification", [])
            ]
        )
    if subsystem == "audit":
        return _normalize_verification(templates.get("audit", {}).get("verification", []))
    if subsystem == "logging":
        return _normalize_verification(templates.get("logging", {}).get("verification", []))
    commands = unique_sorted([item.get("check", {}).get("command") for item in findings if item.get("check", {}).get("command") not in (None, "", "not provided", "unknown")])
    if commands:
        return _normalize_verification(commands, expected_result="Original scanner check confirms compliance")
    return [_verification_step("repeat Wazuh SCA scan", expected_result="Affected checks pass", manual=True)]


def _template_for_action(action_key: str) -> dict[str, Any]:
    templates = _templates()
    if action_key.startswith("firewall:"):
        backend = action_key.split(":", 1)[1]
        firewall = templates.get("firewall", {})
        if backend == "choose":
            return firewall
        backend_template = (firewall.get("backends") or {}).get(backend, {})
        return {**firewall, **backend_template}
    return templates.get(action_key, {})


def _commands_for_config(action_key: str, finding: dict[str, Any]) -> list[str]:
    template = _template_for_action(action_key)
    return template.get("commands", []) or finding.get("remediation", {}).get("commands", [])


def _rollback_for_config(action_key: str) -> str:
    template = _template_for_action(action_key)
    return template.get("rollback") or "Restore previous configuration file or system snapshot if change causes regression"


def _config_title_summary(action_key: str, findings: list[dict[str, Any]]) -> tuple[str, str]:
    template = _template_for_action(action_key)
    if template.get("title") or template.get("summary"):
        return template.get("title") or findings[0].get("title"), template.get("summary") or findings[0].get("remediation", {}).get("summary", "")
    titles = {
        "aide": "Configure AIDE integrity monitoring",
        "apparmor": "Configure AppArmor mandatory access control",
        "core_dumps": "Disable and harden core dump handling",
        "ssh": "Harden sshd_config",
        "pam": "Configure PAM password and lockout policy",
        "time_sync": "Configure time synchronization",
        "cron_at": "Harden cron and at access",
        "firewall": "Choose and configure a single firewall backend",
        "firewall:nftables": "Configure nftables firewall backend",
        "firewall:ufw": "Configure UFW firewall backend",
        "firewall:iptables": "Configure iptables firewall backend",
        "login_banners": "Configure login banners",
        "insecure_services": "Remove insecure clients and services",
        "auditd": "Configure auditd and audit rules",
        "audit_50_scope": "Configure audit scope rules",
        "audit_50_user_emulation": "Configure audit user emulation rules",
        "audit_50_identity": "Configure audit identity rules",
        "audit_99_finalize": "Finalize audit rules",
        "tmp_mount_options": "Harden temporary filesystems",
        "system_partitions": "Separate and harden system log/data partitions",
        "filesystem_mount_options": "Harden filesystem mount options",
        "kernel_modules": "Disable unused kernel modules",
        "logging": "Configure system logging",
    }
    title = titles.get(action_key, findings[0].get("title") or "Apply configuration change")
    summary = f"Apply {len(findings)} related configuration checks as one operational change"
    return title, summary


def _package_commands(findings: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]], str]:
    templates = _templates().get("package_update", {})
    packages = unique_sorted([item.get("package", {}).get("name") for item in findings])
    package_text = " ".join(packages) or "<package>"
    pattern = "|".join(re.escape(package) for package in packages) or "<package>"
    commands = [item.format(packages=package_text, package_pattern=pattern) for item in templates.get("commands", [])]
    verification = _normalize_verification([item.format(packages=package_text, package_pattern=pattern) for item in templates.get("verification", [])])
    return commands, verification, templates.get("rollback", "restore from backup or snapshot if required")


def _fixed_version(condition: Any) -> str:
    text = str(condition or "")
    match = re.search(r"less than\s+(.+)$", text, re.I)
    if match:
        return match.group(1).strip().rstrip(".")
    return text if text and text != "not provided" else ""


def _package_vulnerabilities(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vulnerabilities: dict[str, dict[str, Any]] = {}
    for item in items:
        severity = item.get("severity", {}) if isinstance(item.get("severity"), dict) else {}
        cve = str(item.get("cve") or item.get("finding_uid"))
        vulnerability = vulnerabilities.setdefault(
            cve,
            {
                "id": cve,
                "severity": severity.get("level", "info"),
                "cvss": severity.get("score"),
                "status": "under_evaluation" if item.get("under_evaluation") else "evaluated",
                "description": item.get("description", ""),
                "fixed_version": _fixed_version(item.get("package", {}).get("fixed_condition")),
                "raw_ref": item.get("raw_ref"),
            },
        )
        if severity_rank(severity.get("level")) > severity_rank(vulnerability.get("severity")):
            vulnerability["severity"] = severity.get("level", "info")
        try:
            score = float(severity.get("score"))
        except (TypeError, ValueError):
            score = None
        try:
            current = float(vulnerability.get("cvss"))
        except (TypeError, ValueError):
            current = None
        if score is not None and (current is None or score > current):
            vulnerability["cvss"] = score
    return sorted(vulnerabilities.values(), key=lambda item: (-severity_rank(item.get("severity")), -(float(item.get("cvss") or -1)), item.get("id", "")))


def build_remediation_groups(findings: list[dict[str, Any]], policy_options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Group findings by remediation action."""
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for finding in findings:
        key = remediation_key(finding, policy_options)
        if key is None:
            continue
        buckets.setdefault(key, []).append(finding)

    groups: list[dict[str, Any]] = []
    for key, items in buckets.items():
        action_type = key[0]
        affected_assets = unique_sorted([asset for item in items for asset in item.get("affected_assets", [])])
        severity_max = max((item.get("severity", {}).get("level", "info") for item in items), key=severity_rank, default="info")
        if action_type == "package_update":
            _, agent_id, asset, package_name, package_version, package_arch = key
            commands, verification, rollback = _package_commands(items)
            vulnerabilities = _package_vulnerabilities(items)
            severity_counts = Counter(vulnerability.get("severity", "info") for vulnerability in vulnerabilities)
            max_cvss = max((float(vulnerability.get("cvss")) for vulnerability in vulnerabilities if vulnerability.get("cvss") not in (None, "", "unknown")), default=None)
            title = f"Update package {package_name} on {asset}"
            summary = f"Update package {package_name} to a fixed version or latest security update"
            group_id = stable_id("PKG-GRP", agent_id, package_name, package_version, package_arch)
        elif action_type == "config_change":
            sample = items[0]
            title, summary = _config_title_summary(str(key[1]), items)
            commands = _commands_for_config(str(key[1]), sample)
            verification = _verification_for_config_group(str(key[1]), items)
            rollback = _rollback_for_config(str(key[1]))
            group_id = stable_id("REM-CFG", key[1])
        else:
            title = "Manual review"
            summary = "Review findings manually"
            commands = []
            verification = [_verification_step("repeat Wazuh scan", expected_result="Manual review finding is resolved", manual=True)]
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
        if action_type == "package_update":
            group.update(
                {
                    "type": "software_vulnerability_group",
                    "asset": asset,
                    "agent_id": agent_id,
                    "package": {
                        "name": package_name,
                        "version": package_version,
                        "architecture": package_arch,
                    },
                    "vulnerabilities": vulnerabilities,
                    "top_vulnerabilities": vulnerabilities[:10],
                    "max_severity": severity_max,
                    "max_cvss": max_cvss,
                    "cve_count": len(vulnerabilities),
                    "critical_count": int(severity_counts.get("critical", 0)),
                    "high_count": int(severity_counts.get("high", 0)),
                    "medium_count": int(severity_counts.get("medium", 0)),
                    "low_count": int(severity_counts.get("low", 0)),
                    "under_evaluation_count": sum(1 for vulnerability in vulnerabilities if vulnerability.get("status") == "under_evaluation"),
                    "recommended_action": summary,
                }
            )
        group.update(calculate_priority({**group, "severity": {"level": severity_max, "score": 0}}))
        groups.append(group)

    return sorted(groups, key=lambda item: (-int(item.get("priority_score", 0)), -severity_rank(item["severity_max"]), -len(item["affected_assets"]), item["title"]))
