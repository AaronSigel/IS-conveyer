#!/usr/bin/env python3
import importlib.util
import json
import pathlib


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPORT_FINDINGS_PATH = PROJECT_ROOT / "scripts" / "export-findings.py"
SCHEMA_PATH = PROJECT_ROOT / "report" / "schema" / "finding.schema.json"


def load_export_findings():
    spec = importlib.util.spec_from_file_location("export_findings", EXPORT_FINDINGS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wazuh_vulnerability_hit():
    return {
        "_index": "wazuh-states-vulnerabilities-wazuh",
        "_id": "001_example_CVE-2025-53906_1",
        "_source": {
            "agent": {
                "id": "001",
                "name": "target1",
                "type": "Wazuh",
                "version": "v4.14.5",
            },
            "host": {
                "os": {
                    "full": "Ubuntu 24.04.4 LTS (Noble Numbat)",
                    "kernel": "6.8.0-106-generic",
                    "name": "Ubuntu",
                    "platform": "ubuntu",
                    "type": "ubuntu",
                    "version": "24.04.4",
                }
            },
            "package": {
                "architecture": "amd64",
                "description": "Vi IMproved - enhanced vi editor",
                "name": "vim",
                "size": 4230144,
                "type": "deb",
                "version": "2:9.1.0016-1ubuntu7.10",
            },
            "vulnerability": {
                "category": "Packages",
                "classification": "-",
                "description": "Vim path traversal in zip.vim plugin.",
                "detected_at": "2026-05-03T00:38:46.459Z",
                "enumeration": "CVE",
                "id": "CVE-2025-53906",
                "published_at": "2025-07-15T12:00:00Z",
                "reference": "https://ubuntu.com/security/CVE-2025-53906, https://www.cve.org/CVERecord?id=CVE-2025-53906",
                "scanner": {
                    "condition": "Package less than 2:9.1.0016-1ubuntu7.11",
                    "reference": "https://cti.wazuh.com/vulnerabilities/cves/CVE-2025-53906",
                    "source": "Canonical Security Tracker",
                    "vendor": "Wazuh",
                },
                "score": {
                    "base": 5.5,
                    "version": "3.1",
                },
                "severity": "Medium",
                "under_evaluation": False,
            },
        },
    }


def test_vulnerability_query_does_not_filter_by_profile_cves():
    export_findings = load_export_findings()

    class FakeIndexer:
        def __init__(self):
            self.body = None

        def search(self, index_pattern, body):
            self.body = body
            return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

    indexer = FakeIndexer()
    export_findings.fetch_vulnerabilities(
        indexer,
        ("target1",),
        {"CVE-1999-0001": {"packages": {"unused"}}},
    )

    filters = indexer.body["query"]["bool"]["filter"]
    assert filters == [{"terms": {"agent.name": ["target1"]}}]


def test_wazuh_vulnerability_hit_is_exported_with_full_fields_without_profile_rule():
    export_findings = load_export_findings()

    findings = export_findings.normalize_vulnerability_findings(
        [wazuh_vulnerability_hit()],
        ("target1",),
        {},
    )
    export_findings.validate_findings(findings, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "CVE-2025-53906:vim"
    assert finding["title"] == "CVE-2025-53906 in vim (Vi IMproved - enhanced vi editor)"
    assert finding["severity"] == "medium"
    assert finding["status"] == "fail"
    assert finding["cve"] == "CVE-2025-53906"
    assert finding["cvss"]["base_score"] == 5.5
    assert finding["cvss"]["version"] == "3.1"
    assert finding["detected_at"] == "2026-05-03T00:38:46.459Z"
    assert finding["os_platform"] == "Ubuntu 24.04.4 LTS (Noble Numbat)"
    assert finding["affected_component"]["architecture"] == "amd64"
    assert finding["affected_component"]["description"] == "Vi IMproved - enhanced vi editor"
    assert finding["wazuh_vulnerability"]["_index"] == "wazuh-states-vulnerabilities-wazuh"
    assert finding["wazuh_vulnerability"]["agent"]["version"] == "v4.14.5"
    assert finding["wazuh_vulnerability"]["host"]["os"]["kernel"] == "6.8.0-106-generic"
    assert finding["wazuh_vulnerability"]["package"]["size"] == 4230144
    assert finding["wazuh_vulnerability"]["vulnerability"]["scanner"]["condition"] == "Package less than 2:9.1.0016-1ubuntu7.11"
    assert "https://cti.wazuh.com/vulnerabilities/cves/CVE-2025-53906" in finding["references"]


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
                "condition": "any",
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
    assert finding["wazuh_sca"]["id"] == 35500
    assert finding["wazuh_sca"]["target"] == "modprobe -n -v cramfs"
    assert finding["wazuh_sca"]["result"] == "failed"
    assert finding["wazuh_sca"]["rationale"] == "Uncommon filesystems should be disabled."
    assert finding["wazuh_sca"]["description"] == "Disable cramfs."
    assert finding["wazuh_sca"]["remediation"] == "Add install cramfs /bin/false to a modprobe config file."
    assert finding["wazuh_sca"]["checks"] == ["c:modprobe -n -v cramfs -> r:^install /bin/false"]
    assert finding["wazuh_sca"]["compliance"] == ["cis: 1.1.1.1"]
    assert finding["wazuh_sca"]["condition"] == "any"


def test_sca_compliance_key_value_objects_become_single_pairs():
    export_findings = load_export_findings()
    findings = export_findings.normalize_sca_findings(
        "target1",
        [
            {
                "id": 35500,
                "title": "Ensure cramfs filesystems is disabled.",
                "description": "Disable cramfs.",
                "rationale": "Uncommon filesystems should be disabled.",
                "remediation": "Disable cramfs.",
                "result": "passed",
                "command": "modprobe -n -v cramfs",
                "compliance": [
                    {
                        "key": "iso_27001-2013",
                        "value": "1.1.6,1.2.1,2.2.2,2.2.5",
                    }
                ],
            }
        ],
    )

    finding = findings[0]
    assert finding["wazuh_sca"]["compliance"] == ["iso_27001-2013: 1.1.6,1.2.1,2.2.2,2.2.5"]
    assert finding["evidence"][-1] == "Compliance: iso_27001-2013: 1.1.6,1.2.1,2.2.2,2.2.5"
