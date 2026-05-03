from __future__ import annotations

from typing import Any

from reporting.common import evidence_text, severity_rank


SYSTEM_COMPONENTS = ("kernel", "openssl", "libssl", "sudo", "openssh", "ssh", "pam", "auditd", "systemd")
P1_KEYWORDS = ("privilege escalation", "remote", "network", "rce", "exposure", "authentication bypass")
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


def calculate_priority(finding_or_group: dict[str, Any]) -> str:
    """Calculate P1-P4 technical priority."""
    if is_under_evaluation(finding_or_group):
        return "P4"

    severity = finding_or_group.get("severity_max") or finding_or_group.get("severity", {})
    if isinstance(severity, dict):
        severity = severity.get("level")
    rank = severity_rank(severity)
    text = evidence_text(finding_or_group)
    subsystem = str(finding_or_group.get("subsystem") or "").lower()
    package = str(finding_or_group.get("package", {}).get("name", "") if isinstance(finding_or_group.get("package"), dict) else "")
    system_component = subsystem in P2_SUBSYSTEMS or any(component in package.lower() for component in SYSTEM_COMPONENTS)
    exposed = any(keyword in text for keyword in P1_KEYWORDS)

    if rank >= 4 or (rank >= 3 and (exposed or system_component)):
        return "P1"
    if rank >= 3 or (rank >= 2 and system_component):
        return "P2"
    if rank >= 1:
        return "P3"
    return "P4"
