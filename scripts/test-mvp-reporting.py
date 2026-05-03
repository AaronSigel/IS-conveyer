#!/usr/bin/env python3
import json
import pathlib
import sys


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reporting import build_normalized_report


FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


def load_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_mvp_normalized_contract():
    findings = load_json("unified_findings_sample.json")
    expected = load_json("normalized_report_expected.json")
    report = build_normalized_report(findings, filtered_findings=findings, policy_options={"firewall_backend": "ufw"})

    for key in expected["top_level_keys"]:
        assert key in report, f"Missing normalized_report key: {key}"
    assert len(report["findings"]) == expected["expected_active_findings"]
    assert len([group for group in report["remediation_groups"] if group["action_type"] == "package_update"]) == expected["expected_package_groups"]
    assert len([group for group in report["remediation_groups"] if group["action_type"] == "config_change"]) == expected["expected_configuration_groups"]
    assert report["under_evaluation"] == []
    assert all("data" not in ref for ref in report["raw_refs"])

    asset = report["assets"][0]
    for key, value in expected["expected_asset"].items():
        assert asset[key] == value

    package_group = next(group for group in report["remediation_groups"] if group["action_type"] == "package_update")
    assert package_group["type"] == "software_vulnerability_group"
    assert package_group["package"]["name"] == "sudo"
    assert package_group["cve_count"] == 1
    assert package_group["max_cvss"] == 9.3
    assert package_group["priority"] == "P1"


def main():
    test_mvp_normalized_contract()
    print("mvp reporting tests passed")


if __name__ == "__main__":
    main()
