from __future__ import annotations

from typing import Any, TypedDict


class NormalizedReport(TypedDict, total=False):
    report_id: str
    generated_at: str
    run: dict[str, Any]
    scope: dict[str, Any]
    summary: dict[str, Any]
    remediation_plan: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    under_evaluation: list[dict[str, Any]]
    raw_refs: list[dict[str, Any]]
