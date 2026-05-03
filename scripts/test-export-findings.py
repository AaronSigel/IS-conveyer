#!/usr/bin/env python3
import importlib.util
import pathlib


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPORT_FINDINGS_PATH = PROJECT_ROOT / "scripts" / "export-findings.py"


def load_export_findings():
    spec = importlib.util.spec_from_file_location("export_findings", EXPORT_FINDINGS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vulnerability_pass_findings_are_created_when_no_hits():
    export_findings = load_export_findings()
    vulnerability_rules = {
        "CVE-2025-32463": {
            "rule_id": "VULN_SUDO_CVE_2025_32463",
            "cve": "CVE-2025-32463",
            "title": "Sudo chroot option local privilege escalation",
            "severity": "critical",
            "remediation": "Update sudo to the fixed Ubuntu 24.04 package version or later.",
            "packages": {"sudo"},
            "cvss": {
                "base_score": 7.8,
                "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
        }
    }

    findings = export_findings.build_vulnerability_pass_findings(
        ("target1", "target2"),
        vulnerability_rules,
        [],
    )

    assert len(findings) == 2
    assert {finding["host"] for finding in findings} == {"target1", "target2"}
    assert {finding["status"] for finding in findings} == {"pass"}
    assert {finding["category"] for finding in findings} == {"vulnerability"}
    assert {finding["source"] for finding in findings} == {"wazuh-indexer-vulnerabilities"}
    assert all(finding["external_ids"]["cve"] == "CVE-2025-32463" for finding in findings)
    assert all(finding["cvss"]["base_score"] == 7.8 for finding in findings)
    assert all(finding["affected_component"]["package"] == "sudo" for finding in findings)


def test_vulnerability_pass_findings_skip_failed_host_rule_pairs():
    export_findings = load_export_findings()
    vulnerability_rules = {
        "CVE-2025-32463": {
            "rule_id": "VULN_SUDO_CVE_2025_32463",
            "cve": "CVE-2025-32463",
            "title": "Sudo chroot option local privilege escalation",
            "severity": "critical",
            "remediation": "Update sudo to the fixed Ubuntu 24.04 package version or later.",
            "packages": {"sudo"},
            "cvss": {
                "base_score": 7.8,
                "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
        }
    }
    failed_findings = [
        {
            "host": "target1",
            "rule_id": "VULN_SUDO_CVE_2025_32463",
            "status": "fail",
        }
    ]

    findings = export_findings.build_vulnerability_pass_findings(
        ("target1", "target2"),
        vulnerability_rules,
        failed_findings,
    )

    assert len(findings) == 1
    assert findings[0]["host"] == "target2"
    assert findings[0]["status"] == "pass"


def test_cis_sca_findings_do_not_require_custom_profile_mapping():
    export_findings = load_export_findings()
    findings = export_findings.normalize_sca_findings(
        "target1",
        [
            {
                "id": 35500,
                "title": "1.1.1.1 Ensure cramfs kernel module is not available (Automated)",
                "description": "Disable cramfs.",
                "rationale": "Uncommon filesystems should be disabled.",
                "remediation": "Add install cramfs /bin/false to a modprobe config file.",
                "result": "failed",
                "command": "modprobe -n -v cramfs",
                "compliance": [{"cis": ["1.1.1.1"]}],
                "rules": [{"rule": "c:modprobe -n -v cramfs -> r:^install /bin/false"}],
            }
        ],
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"] == "wazuh_sca"
    assert finding["rule_id"] == "cis_ubuntu24-04:35500"
    assert finding["sca_check_id"] == 35500
    assert finding["title"].startswith("1.1.1.1 Ensure cramfs")
    assert finding["status"] == "fail"
    assert finding["finding_type"] == "configuration_noncompliance"
    assert any("Compliance: cis: 1.1.1.1" == item for item in finding["evidence"])
