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
    description: str
    conditions: str
    severity: str
    priority: str
    cvss_score: Any
    cvss_vector: str
    external_ids: dict[str, Any]
    consequences: str
    security_impact: str
    remediation_summary: str
    remediation_steps: list[str]
    verification_steps: list[dict[str, Any]]
    status: str
    detected_at: str
    references: list[Any]
    passport_type: str
    linked_checks: list[dict[str, Any]]
    completeness_score: float
    completeness_status: str
