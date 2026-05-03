#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from urllib.error import HTTPError

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adapters.wazuh.api_client import (
    WazuhApiClient,
    build_inventory_lookup,
    fetch_sca_checks,
    fetch_syscollector_os,
    fetch_syscollector_packages,
)
from adapters.wazuh.indexer_client import WazuhIndexerClient, fetch_vulnerabilities as _fetch_vulnerabilities
from config.runtime import ARTIFACTS_DIR, CREDS_PATH, PROFILE_PATH, load_env_file, load_profile_rules, parse_hosts, required_api_credentials
from reporting.normalizers.wazuh_sca import first_syscollector_os, normalize_sca_findings
from reporting.normalizers.wazuh_vulnerabilities import build_vulnerability_pass_findings, normalize_vulnerability_findings
from reporting.validation import deduplicate, validate_findings

DEFAULT_OUTPUT = ARTIFACTS_DIR / "unified-findings.json"
DEFAULT_ALERTS_OUTPUT = ARTIFACTS_DIR / "raw-wazuh-alerts.json"
DEFAULT_VULNS_OUTPUT = ARTIFACTS_DIR / "raw-wazuh-vulnerabilities.json"
SCHEMA_PATH = PROJECT_ROOT / "report" / "schema" / "finding.schema.json"

DEFAULT_TARGETS = ("target1", "target2")
DENYLIST_PACKAGES = ("telnet", "telnetd", "rsh-client", "rsh-redone-client", "rsh-server", "vsftpd", "proftpd", "pure-ftpd")


# Backward-compatible symbols used by existing smoke tests.
load_profile = load_profile_rules


def fetch_vulnerabilities(indexer, hosts, vulnerability_rules=None):
    return _fetch_vulnerabilities(indexer, hosts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export normalized findings from the Wazuh API.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--raw-alerts-output", default=str(DEFAULT_ALERTS_OUTPUT))
    parser.add_argument("--raw-vulns-output", default=str(DEFAULT_VULNS_OUTPUT))
    parser.add_argument("--hosts", default=",".join(DEFAULT_TARGETS))
    args = parser.parse_args()

    targets = parse_hosts(args.hosts)
    sca_rules, vulnerability_rules = load_profile_rules(PROFILE_PATH)

    creds = load_env_file(CREDS_PATH)
    missing = required_api_credentials(creds)
    if missing:
        raise RuntimeError(f"Missing Wazuh API credentials: {', '.join(missing)}")

    indexer = None
    if creds.get("WAZUH_INDEXER_URL") and creds.get("WAZUH_INDEXER_USER") and creds.get("WAZUH_INDEXER_PASSWORD"):
        indexer = WazuhIndexerClient(
            creds["WAZUH_INDEXER_URL"],
            creds["WAZUH_INDEXER_USER"],
            creds["WAZUH_INDEXER_PASSWORD"],
            manager_ip=creds.get("WAZUH_MANAGER_IP"),
        )

    client = WazuhApiClient(creds["WAZUH_API_URL"], creds["WAZUH_API_USER"], creds["WAZUH_API_PASSWORD"])

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    agents_by_name, raw_agents = build_inventory_lookup(client, targets)
    raw_api: dict[str, object] = {"agents": raw_agents, "sca": {}, "syscollector_os": {}, "syscollector_packages": {}}
    raw_vulnerabilities: dict[str, object] = {"indexer": None}
    findings: list[dict[str, object]] = []

    for host in targets:
        agent = agents_by_name.get(host)
        if not agent or not agent.get("id"):
            continue
        agent_id = agent["id"]

        os_items, os_response = fetch_syscollector_os(client, agent_id)
        raw_api["syscollector_os"][host] = os_response
        host_os = first_syscollector_os(os_items)

        sca_checks, sca_response = fetch_sca_checks(client, agent_id)
        raw_api["sca"][host] = sca_response
        findings.extend(normalize_sca_findings(host, sca_checks, sca_rules, agent=agent, host_os=host_os))

        raw_api["syscollector_packages"][host] = {}
        for package_name in DENYLIST_PACKAGES:
            _, package_response = fetch_syscollector_packages(client, agent_id, package_name)
            raw_api["syscollector_packages"][host][package_name] = package_response

    if indexer is not None:
        try:
            vulnerability_hits, vulnerability_response = fetch_vulnerabilities(indexer, targets)
        except HTTPError as exc:
            raise RuntimeError(f"Failed to query Wazuh indexer vulnerability data: HTTP {exc.code}") from exc
        raw_vulnerabilities["indexer"] = vulnerability_response
        vulnerability_findings = normalize_vulnerability_findings(vulnerability_hits, targets, vulnerability_rules)
        findings.extend(vulnerability_findings)
        findings.extend(build_vulnerability_pass_findings(targets, vulnerability_rules, vulnerability_findings))

    normalized_findings = deduplicate(findings)
    normalized_findings.sort(key=lambda item: (item["host"], item["status"] != "fail", item["category"], item["rule_id"]))

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validate_findings(normalized_findings, schema)

    pathlib.Path(args.output).write_text(json.dumps(normalized_findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.raw_alerts_output).write_text(json.dumps(raw_api, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.raw_vulns_output).write_text(json.dumps(raw_vulnerabilities, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = Counter((item["host"], item["status"]) for item in normalized_findings)
    print(f"Exported {len(normalized_findings)} normalized findings to {args.output}")
    for host in targets:
        print(f"{host}: fail={summary.get((host, 'fail'), 0)} pass={summary.get((host, 'pass'), 0)}")
    raw_sources = ["Wazuh API"]
    if indexer is not None:
        raw_sources.append("Wazuh indexer")
    print(f"raw sources: {', '.join(raw_sources)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"export-findings.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
