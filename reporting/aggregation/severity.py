from __future__ import annotations

from typing import Any

from reporting.common import evidence_text, severity_rank


SYSTEM_COMPONENTS = ("kernel", "openssl", "libssl", "sudo", "openssh", "ssh", "pam", "auditd", "systemd")
NETWORK_COMPONENTS = ("openssh", "ssh", "curl", "nginx", "apache", "openssl", "libssl", "bind", "dns", "network")
P1_KEYWORDS = ("privilege escalation", "remote", "network", "rce", "exposure", "authentication bypass", "firewall", "ssh", "pam")
P2_SUBSYSTEMS = {"kernel", "access_control", "audit"}


def is_under_evaluation(finding: dict[str, Any]) -> bool:
    severity = str(finding.get("severity", {}).get("level", "") if isinstance(finding.get("severity"), dict) else finding.get("severity", "")).lower()
    score = finding.get("severity", {}).get("score") if isinstance(finding.get("severity"), dict) else finding.get("score")
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        numeric_score = None
    return bool(
        finding.get("under_evaluation")
        or severity in {"", "-", "info", "none", "not provided"}
        or numeric_score == -1
    )


def calculate_priority(finding_or_group: dict[str, Any]) -> dict[str, Any]:
    """Calculate P1-P4 technical priority with score and rationale."""
    if is_under_evaluation(finding_or_group):
        return {"priority": "P4", "priority_score": 10, "priority_reason": "Finding is under evaluation or lacks actionable severity"}

    severity = finding_or_group.get("severity_max") or finding_or_group.get("severity", {})
    if isinstance(severity, dict):
        severity = severity.get("level")
    cvss_score = finding_or_group.get("max_cvss")
    if cvss_score is None and isinstance(finding_or_group.get("severity"), dict):
        cvss_score = finding_or_group.get("severity", {}).get("score")
    try:
        numeric_cvss = float(cvss_score)
    except (TypeError, ValueError):
        numeric_cvss = None
    rank = severity_rank(severity)
    text = evidence_text(finding_or_group)
    subsystem = str(finding_or_group.get("subsystem") or "").lower()
    package = str(finding_or_group.get("package", {}).get("name", "") if isinstance(finding_or_group.get("package"), dict) else "")
    action_type = str(finding_or_group.get("action_type") or finding_or_group.get("type") or "")
    cve_count = int(finding_or_group.get("cve_count") or len(finding_or_group.get("vulnerabilities", []) or []) or 0)
    asset_count = len(finding_or_group.get("affected_assets", []) or finding_or_group.get("asset_refs", []) or [])
    system_component = subsystem in P2_SUBSYSTEMS or any(component in package.lower() for component in SYSTEM_COMPONENTS)
    network_component = any(component in package.lower() or component in text for component in NETWORK_COMPONENTS)
    exposed = any(keyword in text for keyword in P1_KEYWORDS)

    score = 0
    reasons: list[str] = []
    if rank >= 4:
        score += 80
        reasons.append("critical severity")
    elif rank == 3:
        score += 65
        reasons.append("high severity")
    elif rank == 2:
        score += 45
        reasons.append("medium severity")
    elif rank == 1:
        score += 25
        reasons.append("low severity")
    else:
        score += 10
        reasons.append("informational severity")

    if numeric_cvss is not None:
        if numeric_cvss >= 9:
            score += 15
            reasons.append("CVSS >= 9")
        elif numeric_cvss >= 7:
            score += 8
            reasons.append("CVSS >= 7")
    if exposed:
        score += 12
        reasons.append("remote access, authentication, or firewall impact")
    if system_component:
        score += 8
        reasons.append("system security component")
    if network_component and rank >= 3:
        score += 8
        reasons.append("network-facing package or service")
    if cve_count >= 10:
        score += 8
        reasons.append("multiple CVE in one package group")
    elif cve_count >= 3:
        score += 4
        reasons.append("several CVE in one package group")
    if asset_count > 1:
        score += min(10, asset_count * 2)
        reasons.append("multiple affected assets")
    if action_type == "configuration_noncompliance" and subsystem in {"kernel", "access_control", "audit", "firewall"}:
        score += 8
        reasons.append("security hardening subsystem")

    score = max(0, min(score, 100))
    if score >= 80:
        priority = "P1"
    elif score >= 60:
        priority = "P2"
    elif score >= 30:
        priority = "P3"
    else:
        priority = "P4"
    return {"priority": priority, "priority_score": score, "priority_reason": "; ".join(reasons)}
