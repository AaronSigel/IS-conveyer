from __future__ import annotations

from collections import Counter
from typing import Any

from reporting.aggregation.asset_enrichment import normalize_asset_enrichment
from reporting.common import as_text, severity_rank


def _default_record(asset: str) -> dict[str, Any]:
    return {
        "agent.id": "unknown",
        "agent.name": asset,
        "agent.version": "unknown",
        "agent.ip": "unknown",
        "agent.status": "unknown",
        "agent.labels": [],
        "host.os.full": "unknown",
        "host.os.version": "unknown",
        "host.os.kernel": "unknown",
        "host.architecture": "unknown",
        "findings_total": 0,
        "software_vulnerabilities": 0,
        "configuration_noncompliance": 0,
        "max_severity": "info",
    }


def _merge_known(record: dict[str, Any], details: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        value = details.get(key)
        if isinstance(value, list):
            if not record.get(key) and value:
                record[key] = value
            continue
        text = as_text(value, default="unknown")
        if record.get(key) == "unknown" and text != "unknown":
            record[key] = text


def build_asset_inventory(findings: list[dict[str, Any]], asset_enrichment: Any | None = None) -> list[dict[str, Any]]:
    """Build asset inventory from normalized findings."""
    enriched_assets = normalize_asset_enrichment(asset_enrichment)
    assets: dict[str, dict[str, Any]] = {name: {**_default_record(name), **details} for name, details in enriched_assets.items()}
    counters: dict[str, Counter[str]] = {}
    for finding in findings:
        for asset in finding.get("affected_assets", []):
            details = finding.get("asset_details", {}).get(asset, {})
            record = assets.setdefault(asset, _default_record(asset))
            _merge_known(
                record,
                details,
                (
                    "agent.id",
                    "agent.name",
                    "agent.version",
                    "agent.ip",
                    "agent.status",
                    "agent.labels",
                    "host.os.full",
                    "host.os.version",
                    "host.os.kernel",
                    "host.architecture",
                ),
            )
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
