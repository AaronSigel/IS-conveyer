from __future__ import annotations

from typing import TypedDict


class AssetRecord(TypedDict, total=False):
    agent_id: str
    agent_name: str
    host_os_full: str
    host_os_version: str
    host_os_kernel: str
    agent_version: str
    findings_total: int
    software_vulnerabilities: int
    configuration_noncompliance: int
    max_severity: str
