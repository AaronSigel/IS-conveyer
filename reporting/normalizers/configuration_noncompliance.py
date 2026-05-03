from __future__ import annotations

import re
from typing import Any

from reporting.aggregation.subsystem_classifier import classify_subsystem
from reporting.common import UNKNOWN, as_text, first_value, stable_id


def _requirement_id(raw: dict[str, Any], sca: dict[str, Any]) -> str:
    compliance = sca.get("compliance") if isinstance(sca.get("compliance"), list) else []
    for item in compliance:
        match = re.search(r"\bcis\s*:\s*([0-9.]+)", str(item), re.I)
        if match:
            return f"cis {match.group(1)}"
    title = str(first_value(raw.get("title"), sca.get("title"), default=""))
    match = re.match(r"\s*([0-9]+(?:\.[0-9]+)+)\s+", title)
    if match:
        return f"cis {match.group(1)}"
    return as_text(first_value(raw.get("rule_id"), raw.get("sca_check_id"), sca.get("id")))


def _expected_state(sca: dict[str, Any], raw: dict[str, Any]) -> str:
    checks = sca.get("checks") if isinstance(sca.get("checks"), list) else []
    if checks:
        joined = "; ".join(str(item) for item in checks)
        match = re.search(r"->\s*(.+)$", joined)
        return as_text(match.group(1) if match else joined)
    return as_text(first_value(sca.get("condition"), raw.get("condition")), default="not provided")


def normalize_configuration_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a Wazuh SCA configuration finding to a normalized finding."""
    sca = raw.get("wazuh_sca") if isinstance(raw.get("wazuh_sca"), dict) else {}
    asset = as_text(raw.get("host"))
    requirement_id = _requirement_id(raw, sca)
    title = as_text(first_value(raw.get("title"), sca.get("title")))
    command = as_text(first_value(sca.get("target"), sca.get("command"), raw.get("command")), default="not provided")
    expected = _expected_state(sca, raw)
    actual = as_text(first_value(sca.get("result"), raw.get("status")), default="unknown")
    subsystem = classify_subsystem(" ".join([title, command, expected, as_text(raw.get("remediation"), default="")]))
    evidence = list(raw.get("evidence") or [])

    return {
        "finding_uid": stable_id("CFG", requirement_id, command, expected),
        "type": "configuration_noncompliance",
        "class": "configuration_vulnerability",
        "subsystem": subsystem,
        "title": title,
        "requirement": {
            "id": requirement_id,
            "title": title,
        },
        "affected_assets": [asset] if asset != UNKNOWN else [],
        "check": {
            "command": command,
            "expected": expected,
            "actual": actual,
            "result": actual,
        },
        "impact": as_text(first_value(raw.get("impact"), sca.get("rationale")), default="not provided"),
        "description": as_text(first_value(raw.get("description"), sca.get("description")), default="not provided"),
        "severity": {"level": as_text(raw.get("severity"), default="info").lower(), "score": None, "version": "not provided"},
        "detection": {
            "scanner": "Wazuh SCA",
            "source": as_text(raw.get("source"), default="wazuh_sca"),
            "detected_at": [],
        },
        "remediation": {
            "action_type": "config_change",
            "summary": as_text(first_value(raw.get("remediation"), sca.get("remediation")), default="not provided"),
            "file": "unknown",
            "commands": [],
            "verification": [],
        },
        "references": {
            "cis": [requirement_id] if requirement_id.startswith("cis ") else [],
            "mitre": [],
            "nist": [],
            "iso": [],
            "pci_dss": [],
        },
        "evidence": evidence,
        "status": as_text(raw.get("status"), default="unknown"),
        "under_evaluation": bool(raw.get("under_evaluation")),
        "asset_details": {
            asset: {
                "agent.id": "unknown",
                "agent.name": asset,
                "host.os.full": as_text(raw.get("os_platform")),
                "host.os.version": "unknown",
                "host.os.kernel": "unknown",
                "agent.version": "unknown",
            }
        }
        if asset != UNKNOWN
        else {},
        "raw_refs": [{"asset": asset, "source": "wazuh_sca", "data": sca or raw}],
    }
