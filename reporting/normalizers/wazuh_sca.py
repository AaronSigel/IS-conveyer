from __future__ import annotations

from typing import Any

SCA_POLICY_ID = "cis_ubuntu24-04"
SCA_POLICY_NAME = "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"


def normalize_sca_result(value: Any) -> str | None:
    mapping = {"passed": "pass", "failed": "fail"}
    return mapping.get(value)


def normalize_severity(value: Any) -> str:
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
    return mapping.get((value or "").strip().lower(), "medium")


def compliance_values(compliance: Any) -> list[str]:
    values: list[str] = []
    for item in compliance or []:
        if isinstance(item, dict):
            if "key" in item and "value" in item:
                values.append(f"{item['key']}: {item['value']}")
                continue
            for key, value in item.items():
                rendered = ", ".join(str(part) for part in value) if isinstance(value, list) else str(value)
                values.append(f"{key}: {rendered}")
        elif item:
            values.append(str(item))
    return values


def sca_check_values(rules: Any) -> list[str]:
    values: list[str] = []
    for item in rules or []:
        if isinstance(item, dict):
            rule = item.get("rule")
            if rule:
                values.append(str(rule))
        elif item:
            values.append(str(item))
    return values


def sca_rule_id(check_id: Any) -> str:
    return f"{SCA_POLICY_ID}:{check_id}" if check_id is not None else SCA_POLICY_ID


def first_syscollector_os(os_items: list[dict[str, Any]]) -> dict[str, Any]:
    if not os_items:
        return {}
    item = os_items[0]
    return item if isinstance(item, dict) else {}


def syscollector_os_full(host_os: dict[str, Any]) -> str | None:
    full = host_os.get("full")
    if full:
        return full
    name = host_os.get("os_name") or host_os.get("name")
    version = host_os.get("os_version") or host_os.get("version")
    return " ".join(str(part) for part in (name, version) if part) or None


def normalize_sca_findings(host: str, sca_checks: list[dict[str, Any]], sca_rules=None, agent=None, host_os=None) -> list[dict[str, Any]]:
    agent = agent or {}
    host_os = host_os or {}
    findings: list[dict[str, Any]] = []
    for item in sca_checks:
        status = normalize_sca_result(item.get("result"))
        if not status:
            continue
        check_id = item.get("id")
        evidence: list[str] = []
        command = item.get("command")
        if command:
            evidence.append(f"Command: {command}")
        if item.get("reason"):
            evidence.append(item["reason"])
        rule_texts = sca_check_values(item.get("rules"))
        if rule_texts:
            evidence.append(f"Rules: {'; '.join(rule_texts)}")
        compliance = compliance_values(item.get("compliance"))
        if compliance:
            evidence.append(f"Compliance: {'; '.join(compliance)}")

        findings.append(
            {
                "host": host,
                "source": "wazuh_sca",
                "category": "configuration",
                "rule_id": sca_rule_id(check_id),
                "title": item.get("title") or f"{SCA_POLICY_NAME} check {check_id}",
                "severity": normalize_severity(item.get("severity")),
                "status": status,
                "evidence": evidence or [f"SCA result: {item.get('result', 'unknown')}"],
                "remediation": item.get("remediation") or "Follow the CIS Ubuntu Linux 24.04 LTS Benchmark remediation guidance for this check.",
                "finding_type": "configuration_noncompliance",
                "description": item.get("description") or item.get("rationale"),
                "impact": item.get("rationale"),
                "detection_method": f"Wazuh SCA policy {SCA_POLICY_ID}",
                "sca_check_id": check_id,
                "agent": {"id": agent.get("id"), "name": agent.get("name") or host, "version": agent.get("version")},
                "host_os": {
                    "full": syscollector_os_full(host_os),
                    "name": host_os.get("os_name") or host_os.get("name"),
                    "version": host_os.get("os_version") or host_os.get("version"),
                    "kernel": host_os.get("os_kernel") or host_os.get("kernel"),
                    "platform": host_os.get("os_platform") or host_os.get("platform"),
                },
                "wazuh_sca": {
                    "id": check_id,
                    "title": item.get("title"),
                    "target": item.get("target") or command,
                    "result": item.get("result"),
                    "rationale": item.get("rationale"),
                    "remediation": item.get("remediation"),
                    "description": item.get("description"),
                    "checks": rule_texts,
                    "compliance": compliance,
                    "condition": item.get("condition"),
                },
            }
        )
    return findings
