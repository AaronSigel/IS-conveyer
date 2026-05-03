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


def test_configuration_asset_metadata():
    raw = copy.deepcopy(configuration_raw())
    raw["agent"] = {"id": "001", "name": "target1", "version": "v4.14.5"}
    raw["host_os"] = {
        "full": "Ubuntu 24.04.4 LTS (Noble Numbat)",
        "version": "24.04.4",
        "kernel": "6.8.0-106-generic",
    }
    report = build_normalized_report([raw], filtered_findings=[raw])
    asset = report["scope"]["assets"][0]
    assert asset["agent.id"] == "001"
    assert asset["agent.version"] == "v4.14.5"
    assert asset["host.os.full"] == "Ubuntu 24.04.4 LTS (Noble Numbat)"
    assert asset["host.os.version"] == "24.04.4"
    assert asset["host.os.kernel"] == "6.8.0-106-generic"


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


def test_remediation_knowledge_base_verification():
    aide_raw = copy.deepcopy(configuration_raw())
    aide_raw["title"] = "6.3.1.1 Ensure AIDE is installed"
    aide_raw["remediation"] = "Install AIDE and enable scheduled checks."
    aide_raw["wazuh_sca"]["title"] = aide_raw["title"]
    aide_raw["wazuh_sca"]["target"] = "dpkg-query -s aide aide-common"
    aide_raw["wazuh_sca"]["checks"] = ["Package aide is installed"]
    aide = normalize_configuration_finding(aide_raw)

    core_raw = copy.deepcopy(configuration_raw())
    core_raw["title"] = "1.5.3 Ensure core dumps are restricted"
    core_raw["remediation"] = "Set fs.suid_dumpable and configure systemd-coredump."
    core_raw["wazuh_sca"]["title"] = core_raw["title"]
    core_raw["wazuh_sca"]["target"] = "sysctl fs.suid_dumpable"
    core_raw["wazuh_sca"]["checks"] = ["fs.suid_dumpable = 0"]
    core = normalize_configuration_finding(core_raw)

    groups = build_remediation_groups([aide, core])
    aide_group = next(group for group in groups if group["title"] == "Configure AIDE integrity monitoring")
    core_group = next(group for group in groups if group["title"] == "Disable and harden core dump handling")
    assert "findmnt -kn /tmp" not in "\n".join(aide_group["verification"])
    assert "dpkg -s aide aide-common" in aide_group["verification"]
    assert "modprobe -n -v" not in "\n".join(core_group["verification"])
    assert "sysctl fs.suid_dumpable" in core_group["verification"]


def test_related_package_grouping():
    raw = package_raw()
    openssl = copy.deepcopy(raw)
    openssl["affected_component"]["package"] = "openssl"
    openssl["affected_component"]["name"] = "openssl"
    openssl["wazuh_vulnerability"]["package"]["name"] = "openssl"
    libssl = copy.deepcopy(raw)
    libssl["affected_component"]["package"] = "libssl3"
    libssl["affected_component"]["name"] = "libssl3"
    libssl["wazuh_vulnerability"]["package"]["name"] = "libssl3"
    groups = build_remediation_groups([normalize_package_finding(openssl), normalize_package_finding(libssl)])
    assert len(groups) == 1
    assert groups[0]["title"] == "Update openssl packages"
    assert "libssl3 openssl" in " ".join(groups[0]["commands"])


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
    test_configuration_asset_metadata()
    test_package_deduplication_across_hosts()
    test_configuration_deduplication_across_hosts()
    test_priority_and_remediation_groups()
    test_remediation_knowledge_base_verification()
    test_related_package_grouping()
    test_under_evaluation_is_separate()
    print("reporting unit tests passed")


if __name__ == "__main__":
    main()
