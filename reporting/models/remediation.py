from __future__ import annotations

from typing import TypedDict


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
    verification: list[str]
    rollback: str
