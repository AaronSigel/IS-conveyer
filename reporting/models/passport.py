from __future__ import annotations

from typing import Any, TypedDict


class VulnerabilityPassport(TypedDict, total=False):
    passport_id: str
    finding_refs: list[str]
    raw_refs: list[dict[str, Any]]
    title_ru: str
    title_en: str
    vulnerability_class: str
    weakness_type: str
    object: str
    asset: str
    component: str
    software_name: str
    software_version: str
    fixed_version: str
    architecture: str
    os: str
    platform: str
    location: str
    detection_method: str
    source: str
    actual_state: str
    expected_state: str
    expected_state_human: str
    expected_state_raw: str
    description: str
    description_human: str
    description_raw: str
    description_short: str
    description_full: str
    conditions: str
    severity: str
    priority: str
    cvss_score: Any
    cvss_vector: str
    external_ids: dict[str, Any]
    consequences: str
    impact_human: str
    impact_raw: str
    security_impact: str
    remediation_summary: str
    remediation_human: str
    remediation_raw: str
    remediation_steps: list[str]
    verification_steps: list[dict[str, Any]]
    verification_human: list[dict[str, Any]]
    verification_raw: list[dict[str, Any]]
    source_references: list[Any]
    status: str
    detected_at: str
    references: list[Any]
    passport_type: str
    linked_checks: list[dict[str, Any]]
    completeness_score: float
    mandatory_completeness: float
    extended_completeness: float
    missing_extended_fields: list[str]
    completeness_note: str
    completeness_status: str
