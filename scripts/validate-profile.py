#!/usr/bin/env python3
import argparse
import pathlib
import sys

import yaml


REQUIRED_FIELDS = ("id", "title", "category", "severity", "rationale", "remediation", "sca_check_id")
VULNERABILITY_REQUIRED_FIELDS = ("id", "cve", "title", "severity", "remediation")
ALLOWED_CATEGORIES = {"configuration", "software"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def validate_profile(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Profile YAML must be a mapping")

    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("Profile must contain a non-empty checks list")

    rule_ids = set()
    sca_check_ids = set()
    errors = []

    for index, check in enumerate(checks, start=1):
        if not isinstance(check, dict):
            errors.append(f"check #{index}: must be a mapping")
            continue

        for field in REQUIRED_FIELDS:
            if check.get(field) in (None, ""):
                errors.append(f"check #{index}: missing required field {field}")

        rule_id = check.get("id")
        if rule_id in rule_ids:
            errors.append(f"check #{index}: duplicate id {rule_id}")
        elif rule_id:
            rule_ids.add(rule_id)

        sca_check_id = check.get("sca_check_id")
        if sca_check_id in sca_check_ids:
            errors.append(f"check #{index}: duplicate sca_check_id {sca_check_id}")
        elif sca_check_id is not None:
            sca_check_ids.add(sca_check_id)

        category = check.get("category")
        if category and category not in ALLOWED_CATEGORIES:
            errors.append(f"check #{index}: invalid category {category}")

        severity = check.get("severity")
        if severity and severity not in ALLOWED_SEVERITIES:
            errors.append(f"check #{index}: invalid severity {severity}")

    vulnerabilities = data.get("vulnerabilities", [])
    if vulnerabilities is None:
        vulnerabilities = []
    if not isinstance(vulnerabilities, list):
        errors.append("vulnerabilities: must be a list")
    else:
        vulnerability_ids = set()
        vulnerability_cves = set()
        for index, vulnerability in enumerate(vulnerabilities, start=1):
            if not isinstance(vulnerability, dict):
                errors.append(f"vulnerability #{index}: must be a mapping")
                continue

            for field in VULNERABILITY_REQUIRED_FIELDS:
                if vulnerability.get(field) in (None, ""):
                    errors.append(f"vulnerability #{index}: missing required field {field}")

            rule_id = vulnerability.get("id")
            if rule_id in vulnerability_ids:
                errors.append(f"vulnerability #{index}: duplicate id {rule_id}")
            elif rule_id:
                vulnerability_ids.add(rule_id)

            cve = str(vulnerability.get("cve")).upper() if vulnerability.get("cve") else None
            if cve in vulnerability_cves:
                errors.append(f"vulnerability #{index}: duplicate cve {vulnerability.get('cve')}")
            elif cve:
                vulnerability_cves.add(cve)

            severity = vulnerability.get("severity")
            if severity and severity not in ALLOWED_SEVERITIES:
                errors.append(f"vulnerability #{index}: invalid severity {severity}")

            packages = vulnerability.get("packages", [])
            if packages is None:
                packages = []
            if not isinstance(packages, list) or not all(isinstance(package, str) and package for package in packages):
                errors.append(f"vulnerability #{index}: packages must be a list of non-empty strings")

            cvss = vulnerability.get("cvss", {})
            if cvss is None:
                cvss = {}
            if not isinstance(cvss, dict):
                errors.append(f"vulnerability #{index}: cvss must be a mapping")
            else:
                base_score = cvss.get("base_score")
                if base_score is not None:
                    if not isinstance(base_score, (int, float)) or not 0 <= float(base_score) <= 10:
                        errors.append(f"vulnerability #{index}: cvss.base_score must be a number from 0 to 10")
                vector = cvss.get("vector")
                if vector is not None and (not isinstance(vector, str) or not vector):
                    errors.append(f"vulnerability #{index}: cvss.vector must be a non-empty string")

    if errors:
        raise ValueError("\n".join(errors))

    return len(checks), len(vulnerabilities) if isinstance(vulnerabilities, list) else 0


def main():
    parser = argparse.ArgumentParser(description="Validate a host baseline profile YAML file.")
    parser.add_argument("profile", help="Path to profile YAML")
    args = parser.parse_args()

    path = pathlib.Path(args.profile)
    check_count, vulnerability_count = validate_profile(path)
    print(f"Profile {path} is valid: {check_count} checks, {vulnerability_count} vulnerabilities")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"validate-profile.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
