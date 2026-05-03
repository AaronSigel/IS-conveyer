from __future__ import annotations

from typing import Any, TypedDict


class NormalizedReport(TypedDict, total=False):
    report_id: str
    generated_at: str
    run: dict[str, Any]
    scope: dict[str, Any]
    assets: list[dict[str, Any]]
    summary: dict[str, Any]
    passport_matrix: list[dict[str, Any]]
    vulnerability_passports: list[dict[str, Any]]
    summary_passports: list[dict[str, Any]]
    passport_registry_meta: dict[str, Any]
    summary_remediation_plan: list[dict[str, Any]]
    summary_verification_checklist: list[dict[str, Any]]
    remediation_plan: list[dict[str, Any]]
    remediation_groups: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    exceptions: list[dict[str, Any]]
    exceptions_summary: list[dict[str, Any]]
    under_evaluation: list[dict[str, Any]]
    raw_refs: list[dict[str, Any]]
