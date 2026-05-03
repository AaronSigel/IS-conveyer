from __future__ import annotations

from typing import Any, TypedDict


class NormalizedFinding(TypedDict, total=False):
    finding_uid: str
    type: str
    source: str
    status: str
    title: str
    affected_assets: list[str]
    asset_refs: list[str]
    severity: dict[str, Any]
    applicability: dict[str, Any]
    remediation: dict[str, Any]
    raw_ref: str
    raw_refs: list[dict[str, Any]]
