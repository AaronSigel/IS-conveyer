from __future__ import annotations

import re
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUS_ALIASES = {"failed": "fail", "failure": "fail", "passed": "pass"}
SOURCE_ALIASES = {
    "wazuh_sca": {"wazuh_sca", "wazuh-api-sca", "wazuh-api", "wazuh sca"},
    "wazuh_vulnerability": {
        "wazuh_vulnerability",
        "wazuh-indexer-vulnerabilities",
        "wazuh-vulnerability",
        "wazuh vulnerability",
    },
}


def normalize_status(value: Any) -> str:
    lowered = str(value or "").strip().lower()
    return STATUS_ALIASES.get(lowered, lowered)


def source_tokens(value: Any) -> set[str]:
    lowered = str(value or "").strip().lower()
    tokens = {lowered}
    for canonical, aliases in SOURCE_ALIASES.items():
        if lowered == canonical or lowered in aliases:
            tokens.update(aliases)
            tokens.add(canonical)
    return tokens


def infer_finding_type(finding: dict[str, Any]) -> str:
    explicit = finding.get("finding_type")
    if explicit:
        return str(explicit).lower()
    source = str(finding.get("source", "")).lower()
    category = str(finding.get("category", "")).lower()
    if "vulnerab" in source or category == "vulnerability":
        return "software_vulnerability"
    if category == "software":
        return "insecure_package"
    return "configuration_noncompliance"


def get_cvss_base_score(finding: dict[str, Any]) -> float | None:
    cvss = finding.get("cvss_base_score")
    if cvss is not None:
        try:
            return float(cvss)
        except (TypeError, ValueError):
            pass

    cvss = finding.get("cvss")
    if isinstance(cvss, dict) and cvss.get("base_score") is not None:
        try:
            return float(cvss["base_score"])
        except (TypeError, ValueError):
            pass

    wazuh_vulnerability = finding.get("wazuh_vulnerability") if isinstance(finding.get("wazuh_vulnerability"), dict) else {}
    wazuh_vuln = wazuh_vulnerability.get("vulnerability") if isinstance(wazuh_vulnerability.get("vulnerability"), dict) else {}
    score = wazuh_vuln.get("score") if isinstance(wazuh_vuln.get("score"), dict) else {}
    if score.get("base") is not None:
        try:
            return float(score["base"])
        except (TypeError, ValueError):
            pass

    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    for value in evidence:
        match = re.search(r"CVSS\s*base:\s*([0-9]+(?:\.[0-9]+)?)", str(value), re.I)
        if match:
            return float(match.group(1))
    return None


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def normalize_severity(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity") or "info").lower()
    if infer_finding_type(finding) == "software_vulnerability":
        cvss = get_cvss_base_score(finding)
        mapped = severity_from_cvss(cvss)
        if mapped:
            return mapped
    return severity


def extract_cve(finding: dict[str, Any]) -> str | None:
    cve = finding.get("cve")
    if cve:
        return str(cve).upper()

    external_ids = finding.get("external_ids") if isinstance(finding.get("external_ids"), dict) else {}
    if external_ids.get("cve"):
        return str(external_ids["cve"]).upper()

    wazuh_vulnerability = finding.get("wazuh_vulnerability") if isinstance(finding.get("wazuh_vulnerability"), dict) else {}
    wazuh_vuln = wazuh_vulnerability.get("vulnerability") if isinstance(wazuh_vulnerability.get("vulnerability"), dict) else {}
    if wazuh_vuln.get("id"):
        return str(wazuh_vuln["id"]).upper()

    rule_id = str(finding.get("rule_id") or "")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    match = re.search(r"(CVE-\d{4}-\d+)", rule_id + " " + " ".join(map(str, evidence)), re.I)
    return match.group(1).upper() if match else None


def extract_package(finding: dict[str, Any]) -> str | None:
    package = finding.get("package")
    if package:
        return str(package)

    component = finding.get("affected_component") if isinstance(finding.get("affected_component"), dict) else {}
    package = component.get("package") or component.get("name")
    if package:
        return str(package)

    wazuh_vulnerability = finding.get("wazuh_vulnerability") if isinstance(finding.get("wazuh_vulnerability"), dict) else {}
    wazuh_package = wazuh_vulnerability.get("package") if isinstance(wazuh_vulnerability.get("package"), dict) else {}
    if wazuh_package.get("name"):
        return str(wazuh_package["name"])

    rule_id = str(finding.get("rule_id") or "")
    if ":" in rule_id and rule_id.upper().startswith("CVE-"):
        return rule_id.split(":", 1)[1]

    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    for value in evidence:
        match = re.search(r"Package:\s*([^\s]+)", str(value), re.I)
        if match:
            return match.group(1)
        match = re.search(r"Packages filter:\s*(.+)", str(value), re.I)
        if match:
            return match.group(1).strip()
    return None


def normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
    finding = dict(item)
    wazuh_vulnerability = finding.get("wazuh_vulnerability") if isinstance(finding.get("wazuh_vulnerability"), dict) else {}
    wazuh_vuln = wazuh_vulnerability.get("vulnerability") if isinstance(wazuh_vulnerability.get("vulnerability"), dict) else {}
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []

    finding_type = infer_finding_type(finding)
    cvss = get_cvss_base_score(finding)
    finding.update(
        {
            "host": str(finding.get("host") or ""),
            "source": str(finding.get("source") or ""),
            "category": str(finding.get("category") or ""),
            "rule_id": str(finding.get("rule_id") or ""),
            "title": str(finding.get("title") or ""),
            "status": normalize_status(finding.get("status")),
            "severity": normalize_severity({**finding, "finding_type": finding_type, "cvss_base_score": cvss}),
            "finding_type": finding_type,
            "cvss_base_score": cvss,
            "cve": extract_cve(finding),
            "package": extract_package(finding),
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
        if field == "source":
            actual_set = source_tokens(actual)
            return any(source_tokens(v) & actual_set for v in (expected or []))
        return str(actual).lower() in scalar_list(expected)
    if op == "eq":
        if field == "source":
            return bool(source_tokens(actual) & source_tokens(expected))
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


def apply_filters(findings: list[dict[str, Any]], filters: dict[str, Any], *, assume_normalized: bool = False) -> list[dict[str, Any]]:
    normalized = findings if assume_normalized else normalize_findings(findings)
    return [item for item in normalized if all(match_filter(item, field, spec) for field, spec in filters.items() if spec)]


def legacy_cli_filters_to_specs(filters: dict[str, Any]) -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    for field in ("status", "severity", "category", "source", "host", "rule_id", "finding_type"):
        if filters.get(field):
            values = filters[field]
            if field == "status":
                values = [normalize_status(v) for v in values]
            specs[field] = {"op": "in", "value": values}
    if "cvss_min" in filters:
        specs["cvss_base_score"] = {"op": "gte", "value": filters["cvss_min"]}
    if "cvss_max" in filters:
        if "cvss_base_score" in specs:
            specs["cvss_base_score"] = {"op": "between", "value": [filters.get("cvss_min", 0), filters["cvss_max"]]}
        else:
            specs["cvss_base_score"] = {"op": "lte", "value": filters["cvss_max"]}
    return specs
