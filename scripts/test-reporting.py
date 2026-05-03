#!/usr/bin/env python3
import copy
import json
import pathlib
import sys


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reporting import build_normalized_report
from reporting.aggregation.deduplicate import deduplicate_findings
from reporting.aggregation.remediation_groups import build_remediation_groups
from reporting.aggregation.severity import calculate_priority
from reporting.normalizers import normalize_configuration_finding, normalize_package_finding


SAMPLE_FINDINGS = PROJECT_ROOT / "report" / "samples" / "sample-findings.json"


def sample_findings():
    return json.loads(SAMPLE_FINDINGS.read_text(encoding="utf-8"))


def package_raw():
    return [item for item in sample_findings() if item.get("finding_type") == "software_vulnerability"][0]


def configuration_raw():
    return [item for item in sample_findings() if item.get("finding_type") == "configuration_noncompliance"][0]


def test_package_normalization():
    finding = normalize_package_finding(package_raw())
    assert finding["type"] == "software_vulnerability"
    assert finding["cve"] == "CVE-2025-32463"
    assert finding["package"]["name"] == "sudo"
    assert finding["package"]["installed_versions"]["target1"] == "1.9.15p5-3ubuntu5"
    assert finding["severity"]["level"] == "critical"
    assert finding["detection"]["source"] == "Canonical Security Tracker"
    assert "Package less than" in finding["detection"]["scanner_condition"]
    assert any("ubuntu.com/security" in ref for ref in finding["references"])


def test_configuration_normalization():
    finding = normalize_configuration_finding(configuration_raw())
    assert finding["type"] == "configuration_noncompliance"
    assert finding["requirement"]["id"] == "cis 1.1.1.1"
    assert finding["check"]["command"] == "modprobe -n -v cramfs"
    assert finding["check"]["result"] == "failed"
    assert finding["subsystem"] == "kernel"
    assert finding["affected_assets"] == ["target1"]


def test_package_deduplication_across_hosts():
    raw = package_raw()
    target1 = normalize_package_finding(raw)
    duplicate = copy.deepcopy(raw)
    duplicate["host"] = "target2"
    duplicate["wazuh_vulnerability"]["agent"]["name"] = "target2"
    target2 = normalize_package_finding(duplicate)
    deduped = deduplicate_findings([target1, target2])
    assert len(deduped) == 1
    assert deduped[0]["affected_assets"] == ["target1", "target2"]
    assert deduped[0]["package"]["installed_versions"]["target2"] == "1.9.15p5-3ubuntu5"


def test_configuration_deduplication_across_hosts():
    raw = configuration_raw()
    target1 = normalize_configuration_finding(raw)
    duplicate = copy.deepcopy(raw)
    duplicate["host"] = "target2"
    target2 = normalize_configuration_finding(duplicate)
    deduped = deduplicate_findings([target1, target2])
    assert len(deduped) == 1
    assert deduped[0]["affected_assets"] == ["target1", "target2"]


def test_priority_and_remediation_groups():
    package = normalize_package_finding(package_raw())
    config = normalize_configuration_finding(configuration_raw())
    assert calculate_priority(package) == "P1"
    assert calculate_priority(config) == "P1"
    groups = build_remediation_groups([package, config])
    assert {group["action_type"] for group in groups} == {"package_update", "config_change"}
    assert any("sudo apt install --only-upgrade sudo" in group["commands"] for group in groups)
    assert any("modprobe -n -v cramfs" in group["verification"] for group in groups)


def test_under_evaluation_is_separate():
    raw = copy.deepcopy(package_raw())
    raw["severity"] = "info"
    raw["cvss"]["base_score"] = -1
    raw["wazuh_vulnerability"]["vulnerability"]["severity"] = "Info"
    raw["wazuh_vulnerability"]["vulnerability"]["score"]["base"] = -1
    raw["wazuh_vulnerability"]["vulnerability"]["under_evaluation"] = True
    report = build_normalized_report([raw], filtered_findings=[raw])
    assert report["findings"] == []
    assert len(report["under_evaluation"]) == 1
    assert report["remediation_plan"] == []


def main():
    test_package_normalization()
    test_configuration_normalization()
    test_package_deduplication_across_hosts()
    test_configuration_deduplication_across_hosts()
    test_priority_and_remediation_groups()
    test_under_evaluation_is_separate()
    print("reporting unit tests passed")


if __name__ == "__main__":
    main()
