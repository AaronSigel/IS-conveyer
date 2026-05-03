from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from reporting.aggregation.applicability import apply_applicability, is_in_remediation_scope
from reporting.aggregation.asset_inventory import build_asset_inventory
from reporting.aggregation.deduplicate import deduplicate_findings
from reporting.aggregation.remediation_groups import build_remediation_groups
from reporting.aggregation.severity import calculate_priority, is_under_evaluation
from reporting.common import severity_rank, stable_id
from reporting.normalizers import normalize_configuration_finding, normalize_package_finding


def normalize_finding(raw: dict[str, Any]) -> dict[str, Any] | None:
    finding_type = str(raw.get("finding_type") or "").lower()
    source = str(raw.get("source") or "").lower()
    category = str(raw.get("category") or "").lower()
    if finding_type == "software_vulnerability" or "vulnerab" in source or category == "vulnerability":
        return normalize_package_finding(raw)
    if finding_type == "configuration_noncompliance" or "sca" in source or category == "configuration":
        return normalize_configuration_finding(raw)
    return None


def _summary(
    raw_count: int,
    filtered_count: int,
    findings: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> dict[str, Any]:
    by_severity = Counter(item.get("severity", {}).get("level", "info") for item in findings)
    by_asset = Counter(asset for item in findings for asset in item.get("affected_assets", []))
    by_type = Counter(item.get("type", "unknown") for item in findings)
    by_subsystem = Counter(item.get("subsystem", "software") if item.get("type") == "configuration_noncompliance" else "software" for item in findings)
    by_applicability = Counter(item.get("applicability", {}).get("status", "applicable") for item in findings)
    return {
        "raw_findings": raw_count,
        "filtered_findings": filtered_count,
        "unique_findings": len(findings),
        "remediation_groups": len(groups),
        "exceptions": len(exceptions),
        "by_severity": dict(sorted(by_severity.items(), key=lambda item: -severity_rank(item[0]))),
        "by_asset": dict(sorted(by_asset.items())),
        "by_type": dict(sorted(by_type.items())),
        "by_subsystem": dict(sorted(by_subsystem.items())),
        "by_applicability": dict(sorted(by_applicability.items())),
    }


def _compact_raw_refs(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: dict[str, dict[str, Any]] = {}
    for finding in findings:
        for raw_ref in finding.get("raw_refs", []) or []:
            if not isinstance(raw_ref, dict):
                continue
            compact = {
                "asset": raw_ref.get("asset"),
                "source": raw_ref.get("source"),
                "file": raw_ref.get("file"),
                "id": raw_ref.get("id"),
                "ref": raw_ref.get("ref") or finding.get("raw_ref"),
                "finding_uid": finding.get("finding_uid"),
            }
            key = "|".join(str(compact.get(part) or "") for part in ("source", "file", "id", "asset", "finding_uid"))
            refs[key] = {key_: value for key_, value in compact.items() if value not in (None, "", [], {})}
    return sorted(refs.values(), key=lambda item: (str(item.get("source", "")), str(item.get("asset", "")), str(item.get("id", ""))))


def _run_context(metadata: dict[str, Any] | None, profile: str | None) -> dict[str, Any]:
    metadata = metadata or {}
    return {
        "run_id": metadata.get("id") or metadata.get("run_id") or "unknown",
        "started_at": metadata.get("started_at") or "unknown",
        "finished_at": metadata.get("finished_at") or metadata.get("completed_at") or "unknown",
        "status": metadata.get("status") or "unknown",
        "profile": metadata.get("profile_id") or profile or "unknown",
    }


def _policy_options(metadata: dict[str, Any] | None, policy_options: dict[str, Any] | None) -> dict[str, Any]:
    metadata = metadata or {}
    options: dict[str, Any] = {}
    for source in (metadata.get("policy_options"), metadata.get("options"), policy_options):
        if isinstance(source, dict):
            options.update(source)
    return options


def build_normalized_report(
    raw_findings: list[dict[str, Any]],
    *,
    filtered_findings: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    asset_enrichment: dict[str, Any] | None = None,
    policy_options: dict[str, Any] | None = None,
    profile: str | None = None,
    report_id: str | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the normalized technical report model from existing unified findings."""
    selected_raw = filtered_findings if filtered_findings is not None else raw_findings
    normalized = [item for item in (normalize_finding(raw) for raw in selected_raw) if item is not None]
    deduped = deduplicate_findings(normalized)
    options = _policy_options(metadata, policy_options)
    apply_applicability(deduped, options)
    for finding in deduped:
        finding.update(calculate_priority(finding))

    active_findings = [item for item in deduped if not is_under_evaluation(item) and str(item.get("status", "")).lower() != "pass"]
    exceptions = [item for item in active_findings if not is_in_remediation_scope(item)]
    main_findings = [item for item in active_findings if is_in_remediation_scope(item)]
    under_evaluation = [item for item in deduped if is_under_evaluation(item)]
    remediation_groups = build_remediation_groups(main_findings, options)
    inventory_source = asset_enrichment or (metadata or {}).get("asset_enrichment")
    assets = build_asset_inventory(deduped, inventory_source)
    generated = generated_at or datetime.now().astimezone()
    raw_refs = _compact_raw_refs(deduped)

    return {
        "report_id": report_id or stable_id("REPORT", _run_context(metadata, profile).get("run_id"), generated.isoformat()),
        "generated_at": generated.isoformat(),
        "run": _run_context(metadata, profile),
        "policy_options": options,
        "scope": {"assets": assets},
        "assets": assets,
        "summary": _summary(len(raw_findings), len(selected_raw), deduped, remediation_groups, exceptions),
        "remediation_plan": remediation_groups,
        "remediation_groups": remediation_groups,
        "findings": main_findings,
        "exceptions": exceptions,
        "under_evaluation": under_evaluation,
        "raw_refs": raw_refs,
    }
