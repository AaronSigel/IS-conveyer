from __future__ import annotations

from typing import TypedDict


class VerificationStep(TypedDict, total=False):
    command: str
    expected_result: str
    requires_root: bool
    safe_to_run: bool
    manual: bool
    notes: str


class RemediationGroup(TypedDict, total=False):
    group_id: str
    action_type: str
    title: str
    priority: str
    severity_max: str
    affected_assets: list[str]
    affected_findings: list[str]
    summary: str
    commands: list[str]
    verification: list[VerificationStep]
    rollback: str
