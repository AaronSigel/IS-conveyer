from __future__ import annotations

import os
import pathlib
from typing import Any

import yaml

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
CREDS_PATH = ARTIFACTS_DIR / "wazuh-credentials.env"
PROFILE_PATH = PROJECT_ROOT / "profiles" / "cis_ubuntu24-04.yml"


def load_env_file(path: str | pathlib.Path) -> dict[str, str]:
    p = pathlib.Path(path)
    data: dict[str, str] = {}
    if not p.exists():
        return data
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def parse_hosts(raw_hosts: str) -> tuple[str, ...]:
    hosts = tuple(host.strip() for host in raw_hosts.split(",") if host.strip())
    if not hosts:
        raise ValueError("At least one host must be provided")
    return hosts


def load_profile_rules(path: str | pathlib.Path = PROFILE_PATH) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
    profile = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    sca_rules: dict[int, dict[str, Any]] = {}
    for check in profile.get("checks", []):
        sca_check_id = check.get("sca_check_id")
        if sca_check_id is None:
            continue
        sca_rules[int(sca_check_id)] = {
            "rule_id": check["id"],
            "title": check["title"],
            "category": check["category"],
            "severity": check["severity"],
            "remediation": check["remediation"],
        }

    vulnerability_rules: dict[str, dict[str, Any]] = {}
    for item in profile.get("vulnerabilities", []) or []:
        cve_id = str(item["cve"]).upper()
        packages = item.get("packages") or []
        vulnerability_rules[cve_id] = {
            "rule_id": item["id"],
            "cve": cve_id,
            "title": item["title"],
            "severity": item["severity"],
            "remediation": item["remediation"],
            "packages": {package.lower() for package in packages},
            "cvss": item.get("cvss") or {},
        }

    return sca_rules, vulnerability_rules


def required_api_credentials(creds: dict[str, str]) -> list[str]:
    required = ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
    return [key for key in required if not creds.get(key)]


def default_vagrant_private_key() -> str:
    return os.environ.get("VAGRANT_INSECURE_PRIVATE_KEY", "~/.vagrant.d/insecure_private_key")
