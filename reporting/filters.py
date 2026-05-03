from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


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
SEVERITIES = ("critical", "high", "medium", "low", "info")


def split_csv(raw: str | None) -> list[str] | None:
    """Convert a comma-separated CLI value into normalized non-empty values."""
    if raw is None:
        return None
    values = [value.strip() for value in raw.split(",") if value.strip()]
    return values or None


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
        return str(explicit)
    source = str(finding.get("source", "")).lower()
    category = str(finding.get("category", "")).lower()
    if "vulnerab" in source or category == "vulnerability":
        return "software_vulnerability"
    if category == "software":
        return "insecure_package"
    return "configuration_noncompliance"


def get_cvss_score(finding: dict[str, Any]) -> float | None:
    cvss = finding.get("cvss")
    if isinstance(cvss, dict) and cvss.get("base_score") is not None:
        try:
            return float(cvss["base_score"])
        except (TypeError, ValueError):
            return None
    for item in finding.get("evidence") or []:
        match = re.search(r"CVSS\s+base:\s*([0-9]+(?:\.[0-9]+)?)", str(item), re.IGNORECASE)
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


def normalized_severity(finding: dict[str, Any]) -> str:
    if infer_finding_type(finding) == "software_vulnerability":
        severity = severity_from_cvss(get_cvss_score(finding))
        if severity:
            return severity
    return str(finding.get("severity", "info")).strip().lower() or "info"


@dataclass(frozen=True)
class FindingFilters:
    status: list[str] | None = None
    severity: list[str] | None = None
    category: list[str] | None = None
    source: list[str] | None = None
    host: list[str] | None = None
    rule_id: list[str] | None = None
    finding_type: list[str] | None = None
    cvss_min: float | None = None
    cvss_max: float | None = None

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "FindingFilters":
        return cls(
            status=_as_list(values.get("status")),
            severity=_as_list(values.get("severity")),
            category=_as_list(values.get("category")),
            source=_as_list(values.get("source")),
            host=_as_list(values.get("host")),
            rule_id=_as_list(values.get("rule_id")),
            finding_type=_as_list(values.get("finding_type")),
            cvss_min=_as_float(values.get("cvss_min")),
            cvss_max=_as_float(values.get("cvss_max")),
        )

    def active(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


def _as_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return split_csv(value)
    if isinstance(value, Iterable):
        values = [str(item).strip() for item in value if str(item).strip()]
        return values or None
    text = str(value).strip()
    return [text] if text else None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    return float(value)


def _list_match(actual: Any, expected_values: list[str], *, normalizer=None, source: bool = False) -> bool:
    if actual is None:
        return False
    if source:
        actual_set = source_tokens(actual)
        return any(source_tokens(value) & actual_set for value in expected_values)
    if normalizer:
        actual_text = normalizer(actual)
        expected = {normalizer(value) for value in expected_values}
    else:
        actual_text = str(actual).strip().lower()
        expected = {str(value).strip().lower() for value in expected_values}
    return actual_text in expected


def matches_filters(finding: dict[str, Any], filters: FindingFilters) -> bool:
    if filters.status and not _list_match(finding.get("status"), filters.status, normalizer=normalize_status):
        return False
    if filters.severity and not _list_match(normalized_severity(finding), filters.severity):
        return False
    if filters.category and not _list_match(finding.get("category"), filters.category):
        return False
    if filters.source and not _list_match(finding.get("source"), filters.source, source=True):
        return False
    if filters.host and not _list_match(finding.get("host"), filters.host):
        return False
    if filters.rule_id and not _list_match(finding.get("rule_id"), filters.rule_id):
        return False
    if filters.finding_type and not _list_match(infer_finding_type(finding), filters.finding_type):
        return False
    if filters.cvss_min is not None or filters.cvss_max is not None:
        score = get_cvss_score(finding)
        if score is None:
            return False
        if filters.cvss_min is not None and score < filters.cvss_min:
            return False
        if filters.cvss_max is not None and score > filters.cvss_max:
            return False
    return True


def apply_filters(findings: list[dict[str, Any]], filters: FindingFilters | dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings matching the report filters without mutating input objects."""
    filter_obj = filters if isinstance(filters, FindingFilters) else FindingFilters.from_mapping(filters)
    return [finding for finding in findings if matches_filters(finding, filter_obj)]
