#!/usr/bin/env python3
import argparse
import base64
import json
import os
import pathlib
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from collections import Counter
from urllib.error import HTTPError, URLError

import yaml


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
DEFAULT_OUTPUT = ARTIFACTS_DIR / "unified-findings.json"
DEFAULT_ALERTS_OUTPUT = ARTIFACTS_DIR / "raw-wazuh-alerts.json"
DEFAULT_VULNS_OUTPUT = ARTIFACTS_DIR / "raw-wazuh-vulnerabilities.json"
CREDS_PATH = ARTIFACTS_DIR / "wazuh-credentials.env"
SCHEMA_PATH = PROJECT_ROOT / "report" / "schema" / "finding.schema.json"
PROFILE_PATH = PROJECT_ROOT / "profiles" / "host-baseline-v1.yml"

DEFAULT_TARGETS = ("target1", "target2")
SCA_POLICY_ID = "host-baseline-v1"
DEFAULT_VAGRANT_PRIVATE_KEY = os.environ.get("VAGRANT_INSECURE_PRIVATE_KEY", "~/.vagrant.d/insecure_private_key")
DENYLIST_PACKAGES = ("telnet", "telnetd", "rsh-client", "rsh-redone-client", "rsh-server", "vsftpd", "proftpd", "pure-ftpd")


def load_profile_sca_rules(path=PROFILE_PATH):
    profile = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = {}
    for check in profile.get("checks", []):
        sca_check_id = check.get("sca_check_id")
        if sca_check_id is None:
            continue
        rules[int(sca_check_id)] = {
            "rule_id": check["id"],
            "title": check["title"],
            "category": check["category"],
            "severity": check["severity"],
            "remediation": check["remediation"],
        }
    return rules


def load_env_file(path):
    data = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


class WazuhApiClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.context = ssl._create_unverified_context()
        self.token = self._authenticate()

    def _request(self, method, path, *, params=None, body=None, auth=None):
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        headers = {}
        if auth:
            request = urllib.request.Request(url, method=method, headers=headers)
            credentials = f"{auth[0]}:{auth[1]}".encode("utf-8")
            encoded = base64.b64encode(credentials).decode("ascii")
            request.add_header("Authorization", f"Basic {encoded}")
        else:
            request = urllib.request.Request(url, method=method, headers=headers)
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            request.data = payload
            request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, context=self.context) as response:
            return response.read().decode("utf-8")

    def _authenticate(self):
        raw = self._request(
            "POST",
            "/security/user/authenticate",
            params={"raw": "true"},
            auth=(self.username, self.password),
        )
        return raw.strip()

    def get(self, path, *, params=None):
        request = urllib.request.Request(
            f"{self.base_url}{path}" + (f"?{urllib.parse.urlencode(params, doseq=True)}" if params else ""),
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        with urllib.request.urlopen(request, context=self.context) as response:
            return json.loads(response.read().decode("utf-8"))


class WazuhIndexerClient:
    def __init__(self, base_url, username, password, *, manager_ip=None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.manager_ip = manager_ip
        self.context = ssl._create_unverified_context()

    def search(self, index_pattern, body):
        credentials = f"{self.username}:{self.password}".encode("utf-8")
        encoded = base64.b64encode(credentials).decode("ascii")
        request = urllib.request.Request(
            f"{self.base_url}/{index_pattern}/_search",
            headers={
                "Authorization": f"Basic {encoded}",
                "Content-Type": "application/json",
            },
            method="POST",
            data=json.dumps(body).encode("utf-8"),
        )
        try:
            with urllib.request.urlopen(request, context=self.context) as response:
                return json.loads(response.read().decode("utf-8"))
        except URLError:
            if not self.manager_ip:
                raise
            return self._search_via_ssh(index_pattern, body)

    def _search_via_ssh(self, index_pattern, body):
        command = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(pathlib.Path(DEFAULT_VAGRANT_PRIVATE_KEY).expanduser()),
            f"vagrant@{self.manager_ip}",
            (
                "sudo curl -sk "
                f"-u {self.username}:{self.password} "
                "-H 'Content-Type: application/json' "
                f"-X POST https://127.0.0.1:9200/{index_pattern}/_search "
                f"-d '{json.dumps(body, separators=(',', ':'))}'"
            ),
        ]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return json.loads(result.stdout)


def normalize_sca_result(value):
    mapping = {
        "passed": "pass",
        "failed": "fail",
    }
    return mapping.get(value)


def deduplicate(findings):
    unique = {}
    for item in findings:
        key = (item["host"], item["source"], item["category"], item["rule_id"])
        if key not in unique or (unique[key]["status"] != "fail" and item["status"] == "fail"):
            unique[key] = item
    return list(unique.values())


def validate_findings(findings, schema):
    required = schema["required"]
    severity_values = set(schema["properties"]["severity"]["enum"])
    status_values = set(schema["properties"]["status"]["enum"])
    for index, finding in enumerate(findings):
        missing = [field for field in required if field not in finding]
        if missing:
            raise ValueError(f"Finding #{index} is missing required fields: {missing}")
        if finding["severity"] not in severity_values:
            raise ValueError(f"Finding #{index} has invalid severity: {finding['severity']}")
        if finding["status"] not in status_values:
            raise ValueError(f"Finding #{index} has invalid status: {finding['status']}")
        if not isinstance(finding["evidence"], list) or not all(isinstance(item, str) for item in finding["evidence"]):
            raise ValueError(f"Finding #{index} has invalid evidence structure")


def normalize_severity(value):
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get((value or "").strip().lower(), "medium")


def parse_hosts(raw_hosts):
    hosts = tuple(host.strip() for host in raw_hosts.split(",") if host.strip())
    if not hosts:
        raise ValueError("At least one host must be provided")
    return hosts


def build_inventory_lookup(client, targets):
    response = client.get(
        "/agents",
        params={"select": "id,name,status,ip,lastKeepAlive", "limit": 100},
    )
    items = response.get("data", {}).get("affected_items", [])
    return {item["name"]: item for item in items if item.get("name") in targets}, response


def fetch_sca_checks(client, agent_id):
    response = client.get(f"/sca/{agent_id}/checks/{SCA_POLICY_ID}", params={"limit": 100})
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_os(client, agent_id):
    response = client.get(f"/syscollector/{agent_id}/os")
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_packages(client, agent_id, package_name):
    response = client.get(f"/syscollector/{agent_id}/packages", params={"search": package_name, "limit": 20})
    return response.get("data", {}).get("affected_items", []), response


def normalize_sca_findings(host, sca_checks, sca_rules):
    findings = []
    for item in sca_checks:
        rule_meta = sca_rules.get(item.get("id"))
        if not rule_meta:
            continue
        status = normalize_sca_result(item.get("result"))
        if not status:
            continue
        evidence = []
        command = item.get("command")
        if command:
            evidence.append(f"Command: {command}")
        if item.get("reason"):
            evidence.append(item["reason"])
        rule_texts = [rule["rule"] for rule in item.get("rules", []) if rule.get("rule")]
        if rule_texts:
            evidence.append(f"Rules: {'; '.join(rule_texts)}")
        findings.append(
            {
                "host": host,
                "source": "wazuh_sca",
                "category": rule_meta["category"],
                "rule_id": rule_meta["rule_id"],
                "title": rule_meta["title"],
                "severity": rule_meta["severity"],
                "status": status,
                "evidence": evidence or [f"SCA result: {item.get('result', 'unknown')}"],
                "remediation": item.get("remediation") or rule_meta["remediation"],
            }
        )
    return findings


def fetch_vulnerabilities(indexer, hosts):
    page_size = 500
    collected_hits = []
    total = None
    pages = 0
    search_after = None

    while True:
        body = {
            "size": page_size,
            "sort": [
                {"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}},
                {"vulnerability.id": {"order": "asc", "unmapped_type": "keyword"}},
                {"_id": {"order": "asc"}},
            ],
            "query": {
                "terms": {
                    "agent.name": list(hosts),
                }
            },
        }
        if search_after:
            body["search_after"] = search_after

        response = indexer.search("wazuh-states-vulnerabilities*", body)
        page_hits = response.get("hits", {}).get("hits", [])
        if total is None:
            total = response.get("hits", {}).get("total", {})

        collected_hits.extend(page_hits)
        pages += 1

        if len(page_hits) < page_size:
            break

        search_after = page_hits[-1].get("sort")
        if not search_after:
            break

    return collected_hits, {"pages": pages, "hits": {"total": total, "hits": collected_hits}}


def normalize_vulnerability_findings(vulnerability_hits, targets):
    findings = []
    for hit in vulnerability_hits:
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        vulnerability = source.get("vulnerability", {})
        package = source.get("package", {})
        host = agent.get("name")
        if host not in targets:
            continue

        package_name = package.get("name", "unknown-package")
        package_version = package.get("version", "unknown-version")
        cve_id = vulnerability.get("id", hit.get("_id", "unknown-vulnerability"))
        evidence = [
            f"Package: {package_name} {package_version}",
            f"CVE: {cve_id}",
        ]
        if vulnerability.get("severity"):
            evidence.append(f"Severity: {vulnerability['severity']}")
        if vulnerability.get("score", {}).get("base") is not None:
            evidence.append(f"CVSS base: {vulnerability['score']['base']}")
        if vulnerability.get("published_at"):
            evidence.append(f"Published: {vulnerability['published_at']}")
        if vulnerability.get("detected_at"):
            evidence.append(f"Detected: {vulnerability['detected_at']}")

        findings.append(
            {
                "host": host,
                "source": "wazuh-indexer-vulnerabilities",
                "category": "vulnerability",
                "rule_id": f"{cve_id}:{package_name}",
                "title": f"{cve_id} affects package {package_name}",
                "severity": normalize_severity(vulnerability.get("severity")),
                "status": "fail",
                "evidence": evidence,
                "remediation": f"Update or remove package {package_name} {package_version} to remediate {cve_id}.",
            }
        )
    return findings


def main():
    parser = argparse.ArgumentParser(description="Export normalized findings from the Wazuh API.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--raw-alerts-output", default=str(DEFAULT_ALERTS_OUTPUT))
    parser.add_argument("--raw-vulns-output", default=str(DEFAULT_VULNS_OUTPUT))
    parser.add_argument("--hosts", default=",".join(DEFAULT_TARGETS))
    args = parser.parse_args()
    targets = parse_hosts(args.hosts)
    sca_rules = load_profile_sca_rules()

    creds = load_env_file(CREDS_PATH)
    required = ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
    missing = [key for key in required if not creds.get(key)]
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

    client = WazuhApiClient(
        creds["WAZUH_API_URL"],
        creds["WAZUH_API_USER"],
        creds["WAZUH_API_PASSWORD"],
    )

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    agents_by_name, raw_agents = build_inventory_lookup(client, targets)
    raw_api = {"agents": raw_agents, "sca": {}, "syscollector_os": {}, "syscollector_packages": {}}
    raw_vulnerabilities = {"indexer": None}
    findings = []

    for host in targets:
        agent = agents_by_name.get(host)
        if not agent or not agent.get("id"):
            continue
        agent_id = agent["id"]

        sca_checks, sca_response = fetch_sca_checks(client, agent_id)
        raw_api["sca"][host] = sca_response
        findings.extend(normalize_sca_findings(host, sca_checks, sca_rules))

        os_items, os_response = fetch_syscollector_os(client, agent_id)
        raw_api["syscollector_os"][host] = os_response

        raw_api["syscollector_packages"][host] = {}
        for package_name in DENYLIST_PACKAGES:
            package_items, package_response = fetch_syscollector_packages(client, agent_id, package_name)
            raw_api["syscollector_packages"][host][package_name] = package_response

    if indexer is not None:
        try:
            vulnerability_hits, vulnerability_response = fetch_vulnerabilities(indexer, targets)
        except HTTPError as exc:
            raise RuntimeError(f"Failed to query Wazuh indexer vulnerability data: HTTP {exc.code}") from exc
        raw_vulnerabilities["indexer"] = vulnerability_response
        findings.extend(normalize_vulnerability_findings(vulnerability_hits, targets))

    findings = deduplicate(findings)
    findings.sort(key=lambda item: (item["host"], item["status"] != "fail", item["category"], item["rule_id"]))

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validate_findings(findings, schema)

    pathlib.Path(args.output).write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.raw_alerts_output).write_text(json.dumps(raw_api, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.raw_vulns_output).write_text(json.dumps(raw_vulnerabilities, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = Counter((item["host"], item["status"]) for item in findings)
    print(f"Exported {len(findings)} normalized findings to {args.output}")
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
