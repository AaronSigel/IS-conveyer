from __future__ import annotations

from collections import Counter
from typing import Any

from reporting.common import as_text, severity_rank


def build_asset_inventory(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build asset inventory from normalized findings."""
    assets: dict[str, dict[str, Any]] = {}
    counters: dict[str, Counter[str]] = {}
    for finding in findings:
        for asset in finding.get("affected_assets", []):
            details = finding.get("asset_details", {}).get(asset, {})
            record = assets.setdefault(
                asset,
                {
                    "agent.id": "unknown",
                    "agent.name": asset,
                    "host.os.full": "unknown",
                    "host.os.version": "unknown",
                    "host.os.kernel": "unknown",
                    "agent.version": "unknown",
                    "findings_total": 0,
                    "software_vulnerabilities": 0,
                    "configuration_noncompliance": 0,
                    "max_severity": "info",
                },
            )
            for key in ("agent.id", "agent.name", "host.os.full", "host.os.version", "host.os.kernel", "agent.version"):
                value = as_text(details.get(key), default="unknown")
                if record.get(key) == "unknown" and value != "unknown":
                    record[key] = value
            record["findings_total"] += 1
            if finding.get("type") == "software_vulnerability":
                record["software_vulnerabilities"] += 1
            elif finding.get("type") == "configuration_noncompliance":
                record["configuration_noncompliance"] += 1
            level = finding.get("severity", {}).get("level", "info")
            if severity_rank(level) > severity_rank(record["max_severity"]):
                record["max_severity"] = level
            counters.setdefault(asset, Counter()).update([finding.get("type", "unknown")])
    return sorted(assets.values(), key=lambda item: item["agent.name"])
