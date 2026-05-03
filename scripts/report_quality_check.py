#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


FORBIDDEN_SUMMARY_TEXT = (
    "Command output matches the remediation target",
    "Package default status",
    "No main findings for the selected filters",
    "PKG-CVE-",
)

RAW_EXPRESSION_RE = re.compile(r"(^|[\s;])(?:not\s+)?(?:r|c|f|p):|compare\s+[<>=]", re.I)


def _load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _failures_for_summary(normalized: dict[str, Any], html: str) -> list[str]:
    failures: list[str] = []
    for marker in FORBIDDEN_SUMMARY_TEXT:
        if marker in html:
            failures.append(f"summary HTML contains forbidden marker: {marker}")

    summary_passports = normalized.get("summary_passports", []) or []
    software_passports = [item for item in summary_passports if item.get("passport_type") in {"software", "software_group"}]
    if len(software_passports) > 10:
        failures.append(f"summary contains too many software passports: {len(software_passports)} > 10")

    summary_plan = normalized.get("summary_remediation_plan") or normalized.get("remediation_plan", [])
    has_rollup = any(item.get("is_collapsed_summary") for item in summary_plan)
    if len(summary_plan) > 15 and not has_rollup:
        failures.append(f"summary remediation plan has {len(summary_plan)} groups without a collapsed row")

    for passport in summary_passports:
        for field in ("title_ru", "component", "location", "detection_method", "remediation_summary"):
            if passport.get(field) in (None, "", [], {}, "unknown", "не установлено по данным источника"):
                failures.append(f"summary passport {passport.get('passport_id')} is missing {field}")
        expected = str(passport.get("expected_state_human") or passport.get("expected_state") or "")
        if len(expected) > 220 and RAW_EXPRESSION_RE.search(expected):
            failures.append(f"summary passport {passport.get('passport_id')} exposes raw expected_state expression")

        title = str(passport.get("title_ru") or passport.get("title_en") or "").lower()
        component = str(passport.get("component") or "").lower()
        location = str(passport.get("location") or "").lower()
        expected_raw = str(passport.get("expected_state_human") or passport.get("expected_state") or "").lower()
        if "ftp" in title and "nftables" in location:
            failures.append("FTP passport contains nftables location")
        if "bootloader" in title or "grub" in title:
            if "pam" in component:
                failures.append("bootloader passport contains PAM component")
        if "баннер" in title or "banner" in title:
            if "system-locale" in expected_raw or "auditctl" in expected_raw:
                failures.append("login banners passport contains audit system-locale rules")

    return failures


def _asset_signature(report: dict[str, Any]) -> list[tuple[Any, ...]]:
    assets = report.get("scope", {}).get("assets") or report.get("assets") or []
    return sorted(
        (
            asset.get("agent_id") or asset.get("agent.id"),
            asset.get("agent_name") or asset.get("agent.name"),
            asset.get("ip") or asset.get("agent.ip"),
            asset.get("status") or asset.get("agent.status"),
            asset.get("os_name") or asset.get("host.os.full"),
            asset.get("os_version") or asset.get("host.os.version"),
            asset.get("architecture") or asset.get("host.architecture"),
            asset.get("kernel") or asset.get("host.os.kernel"),
            asset.get("wazuh_version") or asset.get("agent.version"),
        )
        for asset in assets
    )


def _failures_for_split_inventory(split_dir: pathlib.Path) -> list[str]:
    failures: list[str] = []
    package_reports = sorted(split_dir.glob("*-packages-report.json"))
    for package_report in package_reports:
        config_report = package_report.with_name(package_report.name.replace("-packages-report.json", "-configuration-report.json"))
        if not config_report.exists():
            continue
        packages = _load_json(package_report)
        configuration = _load_json(config_report)
        if _asset_signature(packages) != _asset_signature(configuration):
            failures.append(f"asset inventory differs between {package_report.name} and {config_report.name}")
    return failures


def check_report_quality(normalized: dict[str, Any], html: str, split_dir: pathlib.Path | None = None) -> list[str]:
    failures = _failures_for_summary(normalized, html)
    if split_dir and split_dir.exists():
        failures.extend(_failures_for_split_inventory(split_dir))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate human-readable summary report quality gates.")
    parser.add_argument("--normalized", required=True, type=pathlib.Path)
    parser.add_argument("--html", required=True, type=pathlib.Path)
    parser.add_argument("--split-dir", type=pathlib.Path)
    args = parser.parse_args()

    failures = check_report_quality(_load_json(args.normalized), args.html.read_text(encoding="utf-8"), args.split_dir)
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("report quality check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
