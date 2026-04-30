#!/usr/bin/env python3
import argparse
import pathlib
import sys

import yaml


REQUIRED_FIELDS = ("id", "title", "category", "severity", "rationale", "remediation", "sca_check_id")
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

    if errors:
        raise ValueError("\n".join(errors))

    return len(checks)


def main():
    parser = argparse.ArgumentParser(description="Validate a host baseline profile YAML file.")
    parser.add_argument("profile", help="Path to profile YAML")
    args = parser.parse_args()

    path = pathlib.Path(args.profile)
    count = validate_profile(path)
    print(f"Profile {path} is valid: {count} checks")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"validate-profile.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
