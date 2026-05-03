import re
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

PRESETS = {
    "all_vulnerability": (
        "All vulnerability",
        {"finding_type": {"op": "eq", "value": "software_vulnerability"}},
    ),
    "fail_vulnerability": (
        "Fail vulnerability",
        {
            "finding_type": {"op": "eq", "value": "software_vulnerability"},
            "status": {"op": "in", "value": ["fail"]},
        },
    ),
}


def normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
    finding = dict(item)
    wazuh_vulnerability = finding.get("wazuh_vulnerability") if isinstance(finding.get("wazuh_vulnerability"), dict) else {}
    wazuh_package = wazuh_vulnerability.get("package") if isinstance(wazuh_vulnerability.get("package"), dict) else {}
    wazuh_vuln = wazuh_vulnerability.get("vulnerability") if isinstance(wazuh_vulnerability.get("vulnerability"), dict) else {}
    source = str(finding.get("source") or "")
    rule_id = str(finding.get("rule_id") or "")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    cvss = finding.get("cvss_base_score")
    if cvss is None and isinstance(finding.get("cvss"), dict):
        cvss = finding["cvss"].get("base_score")
    if cvss is None and isinstance(wazuh_vuln.get("score"), dict):
        cvss = wazuh_vuln["score"].get("base")
    if cvss is None:
        for value in evidence:
            match = re.search(r"CVSS base:\s*([0-9]+(?:\.[0-9]+)?)", str(value), re.I)
            if match:
                cvss = float(match.group(1))
                break
    cve = finding.get("cve")
    if not cve:
        cve = wazuh_vuln.get("id")
    if not cve:
        match = re.search(r"(CVE-\d{4}-\d+)", rule_id + " " + " ".join(map(str, evidence)), re.I)
        cve = match.group(1).upper() if match else None
    package = finding.get("package")
    if not package and isinstance(finding.get("affected_component"), dict):
        component = finding["affected_component"]
        package = component.get("package") or component.get("name")
    if not package:
        package = wazuh_package.get("name")
    if not package:
        if ":" in rule_id and rule_id.upper().startswith("CVE-"):
            package = rule_id.split(":", 1)[1]
        else:
            for value in evidence:
                match = re.search(r"Package:\s*([^\s]+)", str(value), re.I)
                if match:
                    package = match.group(1)
                    break
                match = re.search(r"Packages filter:\s*(.+)", str(value), re.I)
                if match:
                    package = match.group(1).strip()
                    break
    severity = str(finding.get("severity") or "info").lower()
    finding_type = str(finding.get("finding_type") or "").lower()
    if not finding_type and ("vulnerab" in source.lower() or str(finding.get("category") or "").lower() == "vulnerability"):
        finding_type = "software_vulnerability"
    if not finding_type:
        finding_type = "configuration_noncompliance"
    if finding_type == "software_vulnerability" and cvss is not None:
        score = float(cvss)
        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        elif score >= 4.0:
            severity = "medium"
        elif score > 0.0:
            severity = "low"
        else:
            severity = "info"
    finding.update(
        {
            "host": str(finding.get("host") or ""),
            "source": source,
            "category": str(finding.get("category") or ""),
            "rule_id": rule_id,
            "title": str(finding.get("title") or ""),
            "status": str(finding.get("status") or "").lower(),
            "severity": severity,
            "finding_type": finding_type,
            "cvss_base_score": cvss,
            "cve": cve,
            "package": package,
            "detected_at": finding.get("detected_at") or wazuh_vuln.get("detected_at"),
            "evidence": evidence,
            "remediation": str(finding.get("remediation") or ""),
        }
    )
    finding["id"] = str(finding.get("id") or f"{finding['host']}:{finding['rule_id']}")
    return finding


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_finding(item) for item in findings]


def scalar_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).lower() for item in value if str(item) != ""]
    return [part.strip().lower() for part in str(value).split(",") if part.strip()]


def match_filter(finding: dict[str, Any], field: str, spec: dict[str, Any]) -> bool:
    op = spec.get("op")
    expected = spec.get("value")
    include_missing = bool(spec.get("include_missing", False))
    actual = finding.get(field)
    if op == "exists":
        return actual not in (None, "", [])
    if op == "not_exists":
        return actual in (None, "", [])
    if op == "in":
        return str(actual).lower() in scalar_list(expected)
    if op == "eq":
        return str(actual).lower() == str(expected).lower()
    if op == "contains":
        return str(expected).lower() in str(actual or "").lower()
    if actual in (None, ""):
        return include_missing
    if op == "gte" and field == "severity":
        return SEVERITY_ORDER.get(str(actual).lower(), -1) >= SEVERITY_ORDER.get(str(expected).lower(), -1)
    if op == "gte":
        return float(actual) >= float(expected)
    if op == "lte":
        return float(actual) <= float(expected)
    if op == "between":
        low, high = expected
        return float(low) <= float(actual) <= float(high)
    return True


def apply_filters(findings: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = normalize_findings(findings)
    return [item for item in normalized if all(match_filter(item, field, spec) for field, spec in filters.items() if spec)]


def filters_from_form(form: dict[str, Any]) -> dict[str, Any]:
    preset = form.get("preset")
    if preset and preset in PRESETS:
        return dict(PRESETS[preset][1])
    return dict(PRESETS["all_vulnerability"][1])
