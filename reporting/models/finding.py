from __future__ import annotations

from typing import Any, TypedDict


class NormalizedFinding(TypedDict, total=False):
    finding_uid: str
    type: str
    title: str
    affected_assets: list[str]
    severity: dict[str, Any]
    applicability: dict[str, Any]
    remediation: dict[str, Any]
