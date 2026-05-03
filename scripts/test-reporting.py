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


def verification_commands(group):
    return [step["command"] for step in group["verification"]]


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


def test_asset_enrichment_prefers_wazuh_inventory():
    raw = copy.deepcopy(configuration_raw())
    raw["agent"] = {"id": "001", "name": "target1", "version": "v4.14.5"}
    raw["host_os"] = {
        "full": "6.8.0-106-generic",
        "version": "unknown",
        "kernel": "unknown",
    }
    enrichment = {
        "agents": {
            "data": {
                "affected_items": [
                    {
                        "id": "001",
                        "name": "target1",
                        "version": "v4.14.5",
                        "ip": "192.168.56.11",
                        "status": "active",
                        "labels": {"env": "lab"},
                    }
                ]
            }
        },
        "syscollector_os": {
            "target1": {
                "data": {
                    "affected_items": [
                        {
                            "os": {
                                "full": "Ubuntu 24.04.4 LTS (Noble Numbat)",
                                "version": "24.04.4",
                                "kernel": "6.8.0-106-generic",
                                "architecture": "x86_64",
                            }
                        }
                    ]
                }
            }
        },
    }
    report = build_normalized_report([raw], filtered_findings=[raw], asset_enrichment=enrichment)
    asset = report["scope"]["assets"][0]
    assert asset["agent.id"] == "001"
    assert asset["agent.ip"] == "192.168.56.11"
    assert asset["agent.status"] == "active"
    assert asset["agent.labels"] == ["env=lab"]
    assert asset["agent.version"] == "v4.14.5"
    assert asset["host.os.full"] == "Ubuntu 24.04.4 LTS (Noble Numbat)"
    assert asset["host.os.kernel"] == "6.8.0-106-generic"
    assert asset["host.architecture"] == "x86_64"


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
    assert any("modprobe -n -v cramfs" in verification_commands(group) for group in groups)


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
    assert "findmnt -kn /tmp" not in "\n".join(verification_commands(aide_group))
    assert "dpkg -s aide aide-common" in verification_commands(aide_group)
    assert "modprobe -n -v" not in "\n".join(verification_commands(core_group))
    assert "sysctl fs.suid_dumpable" in verification_commands(core_group)


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


def test_engineering_remediation_grouping_and_structured_verification():
    apparmor_raw = copy.deepcopy(configuration_raw())
    apparmor_raw["title"] = "1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration"
    apparmor_raw["remediation"] = "Edit grub so AppArmor is enabled."
    apparmor_raw["wazuh_sca"]["title"] = apparmor_raw["title"]
    apparmor_raw["wazuh_sca"]["target"] = "grep apparmor /proc/cmdline"
    apparmor = normalize_configuration_finding(apparmor_raw)

    chrony_raw = copy.deepcopy(configuration_raw())
    chrony_raw["title"] = "2.1.1 Ensure chrony is enabled"
    chrony_raw["remediation"] = "Install and enable chrony."
    chrony_raw["wazuh_sca"]["title"] = chrony_raw["title"]
    chrony_raw["wazuh_sca"]["target"] = "systemctl is-enabled chrony"
    chrony = normalize_configuration_finding(chrony_raw)

    kernel_raw = copy.deepcopy(configuration_raw())
    kernel_raw["title"] = "1.1.1.9 Ensure dccp kernel module is not available"
    kernel_raw["remediation"] = "Disable the dccp kernel module."
    kernel_raw["wazuh_sca"]["title"] = kernel_raw["title"]
    kernel_raw["wazuh_sca"]["target"] = "modprobe -n -v dccp"
    kernel = normalize_configuration_finding(kernel_raw)

    groups = build_remediation_groups([apparmor, chrony, kernel])
    titles = {group["title"] for group in groups}
    assert "Configure AppArmor mandatory access control" in titles
    assert "Configure time synchronization" in titles
    assert "Disable unused kernel modules" in titles

    for group in groups:
        for step in group["verification"]:
            assert set(step) >= {"command", "expected_result", "requires_root", "safe_to_run", "manual", "notes"}
            assert step["command"] != "unknown"
            assert "<module>" not in step["command"]

    kernel_group = next(group for group in groups if group["title"] == "Disable unused kernel modules")
    assert "modprobe -n -v dccp" in verification_commands(kernel_group)


def test_firewall_backend_filters_conflicting_remediation_paths():
    ufw_raw = copy.deepcopy(configuration_raw())
    ufw_raw["title"] = "4.1.3 Ensure ufw loopback traffic is configured"
    ufw_raw["remediation"] = "Configure UFW loopback rules."
    ufw_raw["wazuh_sca"]["title"] = ufw_raw["title"]
    ufw_raw["wazuh_sca"]["target"] = "ufw status verbose"

    nft_raw = copy.deepcopy(configuration_raw())
    nft_raw["title"] = "4.2.1 Ensure nftables is installed"
    nft_raw["remediation"] = "Install and enable nftables."
    nft_raw["wazuh_sca"]["title"] = nft_raw["title"]
    nft_raw["wazuh_sca"]["target"] = "systemctl is-enabled nftables"

    iptables_raw = copy.deepcopy(configuration_raw())
    iptables_raw["title"] = "4.3.1 Ensure iptables default deny firewall policy"
    iptables_raw["remediation"] = "Configure iptables default deny."
    iptables_raw["wazuh_sca"]["title"] = iptables_raw["title"]
    iptables_raw["wazuh_sca"]["target"] = "iptables -L"

    report = build_normalized_report(
        [ufw_raw, nft_raw, iptables_raw],
        filtered_findings=[ufw_raw, nft_raw, iptables_raw],
        policy_options={"firewall_backend": "ufw"},
    )
    firewall_groups = [group for group in report["remediation_groups"] if "firewall" in group["title"].lower()]
    assert len(firewall_groups) == 1
    assert firewall_groups[0]["title"] == "Configure UFW firewall backend"
    assert len(firewall_groups[0]["affected_findings"]) == 1
    assert "ufw status verbose" in verification_commands(firewall_groups[0])
    assert "nft list ruleset" not in verification_commands(firewall_groups[0])
    assert "iptables -L -n -v" not in verification_commands(firewall_groups[0])
    assert report["policy_options"]["firewall_backend"] == "ufw"

    disabled_report = build_normalized_report(
        [ufw_raw, nft_raw, iptables_raw],
        filtered_findings=[ufw_raw, nft_raw, iptables_raw],
        policy_options={"firewall_backend": "none"},
    )
    assert not [group for group in disabled_report["remediation_groups"] if "firewall" in group["title"].lower()]


def test_applicability_exceptions_are_outside_remediation_plan():
    boot_raw = copy.deepcopy(configuration_raw())
    boot_raw["title"] = "1.4.2 Ensure bootloader password is set"
    boot_raw["remediation"] = "Set a GRUB bootloader password."
    boot_raw["wazuh_sca"]["title"] = boot_raw["title"]
    boot_raw["wazuh_sca"]["target"] = "grep superusers /boot/grub/grub.cfg"

    audit_partition_raw = copy.deepcopy(configuration_raw())
    audit_partition_raw["title"] = "1.1.2.4 Ensure separate partition exists for /var/log/audit"
    audit_partition_raw["remediation"] = "Create a separate partition for /var/log/audit."
    audit_partition_raw["wazuh_sca"]["title"] = audit_partition_raw["title"]
    audit_partition_raw["wazuh_sca"]["target"] = "findmnt -kn /var/log/audit"

    report = build_normalized_report(
        [boot_raw, audit_partition_raw],
        filtered_findings=[boot_raw, audit_partition_raw],
    )
    assert report["findings"] == []
    assert report["remediation_plan"] == []
    assert report["summary"]["exceptions"] == 2
    assert {item["applicability"]["status"] for item in report["exceptions"]} == {"manual_review", "environment_specific"}

    override_report = build_normalized_report(
        [boot_raw],
        filtered_findings=[boot_raw],
        policy_options={
            "applicability_overrides": {
                "cis 1.4.2": {
                    "status": "accepted_risk",
                    "reason": "Accepted for isolated lab demonstration.",
                }
            }
        },
    )
    assert override_report["exceptions"][0]["applicability"]["status"] == "accepted_risk"
    assert override_report["exceptions"][0]["applicability"]["reason"] == "Accepted for isolated lab demonstration."


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
    test_asset_enrichment_prefers_wazuh_inventory()
    test_package_deduplication_across_hosts()
    test_configuration_deduplication_across_hosts()
    test_priority_and_remediation_groups()
    test_remediation_knowledge_base_verification()
    test_related_package_grouping()
    test_engineering_remediation_grouping_and_structured_verification()
    test_firewall_backend_filters_conflicting_remediation_paths()
    test_applicability_exceptions_are_outside_remediation_plan()
    test_under_evaluation_is_separate()
    print("reporting unit tests passed")


if __name__ == "__main__":
    main()
