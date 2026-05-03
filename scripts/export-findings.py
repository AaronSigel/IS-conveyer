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
PROFILE_PATH = PROJECT_ROOT / "profiles" / "cis_ubuntu24-04.yml"

DEFAULT_TARGETS = ("target1", "target2")
SCA_POLICY_ID = "cis_ubuntu24-04"
SCA_POLICY_NAME = "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0"
DEFAULT_VAGRANT_PRIVATE_KEY = os.environ.get("VAGRANT_INSECURE_PRIVATE_KEY", "~/.vagrant.d/insecure_private_key")
DENYLIST_PACKAGES = ("telnet", "telnetd", "rsh-client", "rsh-redone-client", "rsh-server", "vsftpd", "proftpd", "pure-ftpd")


def _is_wsl():
    try:
        return "microsoft" in pathlib.Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def _manager_ssh_host_port(manager_ip):
    """SSH target to run indexer queries on the manager VM (see ansible inventory forwarded ports)."""
    override_host = (os.environ.get("WAZUH_MANAGER_SSH_HOST") or "").strip()
    override_port = (os.environ.get("WAZUH_MANAGER_SSH_PORT") or "").strip()
    if override_host:
        return override_host, int(override_port) if override_port else 22

    if manager_ip and _is_wsl() and manager_ip.startswith("192.168.56."):
        return "127.0.0.1", 2222

    return manager_ip or "127.0.0.1", None


def load_profile(path=PROFILE_PATH):
    profile = yaml.safe_load(path.read_text(encoding="utf-8"))
    sca_rules = {}
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

    vulnerability_rules = {}
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
        host, port = _manager_ssh_host_port(self.manager_ip)
        command = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(pathlib.Path(DEFAULT_VAGRANT_PRIVATE_KEY).expanduser()),
        ]
        if port:
            command.extend(["-p", str(port)])
        command.extend(
            [
                f"vagrant@{host}",
                (
                    "sudo curl -sk "
                    f"-u {self.username}:{self.password} "
                    "-H 'Content-Type: application/json' "
                    f"-X POST https://127.0.0.1:9200/{index_pattern}/_search "
                    f"-d '{json.dumps(body, separators=(',', ':'))}'"
                ),
            ]
        )
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
    response = client.get(f"/sca/{agent_id}/checks/{SCA_POLICY_ID}", params={"limit": 1000})
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_os(client, agent_id):
    response = client.get(f"/syscollector/{agent_id}/os")
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_packages(client, agent_id, package_name):
    response = client.get(f"/syscollector/{agent_id}/packages", params={"search": package_name, "limit": 20})
    return response.get("data", {}).get("affected_items", []), response


def compliance_values(compliance):
    values = []
    for item in compliance or []:
        if isinstance(item, dict):
            if "key" in item and "value" in item:
                values.append(f"{item['key']}: {item['value']}")
                continue
            for key, value in item.items():
                if isinstance(value, list):
                    rendered = ", ".join(str(part) for part in value)
                else:
                    rendered = str(value)
                values.append(f"{key}: {rendered}")
        elif item:
            values.append(str(item))
    return values


def sca_check_values(rules):
    values = []
    for item in rules or []:
        if isinstance(item, dict):
            rule = item.get("rule")
            if rule:
                values.append(str(rule))
        elif item:
            values.append(str(item))
    return values


def sca_rule_id(check_id):
    return f"{SCA_POLICY_ID}:{check_id}" if check_id is not None else SCA_POLICY_ID


def normalize_sca_findings(host, sca_checks, sca_rules=None):
    findings = []
    for item in sca_checks:
        status = normalize_sca_result(item.get("result"))
        if not status:
            continue
        check_id = item.get("id")
        evidence = []
        command = item.get("command")
        if command:
            evidence.append(f"Command: {command}")
        if item.get("reason"):
            evidence.append(item["reason"])
        rule_texts = sca_check_values(item.get("rules"))
        if rule_texts:
            evidence.append(f"Rules: {'; '.join(rule_texts)}")
        compliance = compliance_values(item.get("compliance"))
        if compliance:
            evidence.append(f"Compliance: {'; '.join(compliance)}")
        findings.append(
            {
                "host": host,
                "source": "wazuh_sca",
                "category": "configuration",
                "rule_id": sca_rule_id(check_id),
                "title": item.get("title") or f"{SCA_POLICY_NAME} check {check_id}",
                "severity": normalize_severity(item.get("severity")),
                "status": status,
                "evidence": evidence or [f"SCA result: {item.get('result', 'unknown')}"],
                "remediation": item.get("remediation") or "Follow the CIS Ubuntu Linux 24.04 LTS Benchmark remediation guidance for this check.",
                "finding_type": "configuration_noncompliance",
                "description": item.get("description") or item.get("rationale"),
                "impact": item.get("rationale"),
                "detection_method": f"Wazuh SCA policy {SCA_POLICY_ID}",
                "sca_check_id": check_id,
                "wazuh_sca": {
                    "id": check_id,
                    "title": item.get("title"),
                    "target": item.get("target") or command,
                    "result": item.get("result"),
                    "rationale": item.get("rationale"),
                    "remediation": item.get("remediation"),
                    "description": item.get("description"),
                    "checks": rule_texts,
                    "compliance": compliance,
                    "condition": item.get("condition"),
                },
            }
        )
    return findings


def fetch_vulnerabilities(indexer, hosts, vulnerability_rules=None):
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
                "bool": {
                    "filter": [
                        {"terms": {"agent.name": list(hosts)}},
                    ]
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


def split_references(value):
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def cvss_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def vulnerability_rule_id(cve_id, package_name):
    package_part = str(package_name or "unknown-package").strip().lower() or "unknown-package"
    return f"{cve_id}:{package_part}"


def vulnerability_title(cve_id, package):
    package_name = package.get("name") or "unknown package"
    package_description = package.get("description")
    if package_description:
        return f"{cve_id} in {package_name} ({package_description})"
    return f"{cve_id} in {package_name}"


def vulnerability_remediation(package_name, cve_id, scanner, rule_meta):
    if rule_meta and rule_meta.get("remediation"):
        return rule_meta["remediation"]
    condition = scanner.get("condition")
    if condition:
        return f"Update {package_name} to a package version that satisfies the Wazuh scanner condition: {condition}."
    return f"Update {package_name} to a version that is not affected by {cve_id}."


def vulnerability_detection_method(scanner):
    parts = ["Wazuh Vulnerability Detector"]
    source = scanner.get("source")
    vendor = scanner.get("vendor")
    if source:
        parts.append(str(source))
    if vendor and vendor not in parts:
        parts.append(str(vendor))
    return " / ".join(parts)


def normalize_vulnerability_findings(vulnerability_hits, targets, vulnerability_rules):
    findings = []
    for hit in vulnerability_hits:
        source = hit.get("_source", {})
        agent = source.get("agent", {})
        host_os = source.get("host", {}).get("os", {})
        vulnerability = source.get("vulnerability", {})
        scanner = vulnerability.get("scanner", {}) if isinstance(vulnerability.get("scanner"), dict) else {}
        package = source.get("package", {})
        host = agent.get("name")
        if host not in targets:
            continue

        package_name = package.get("name", "unknown-package")
        package_version = package.get("version", "unknown-version")
        cve_id = str(vulnerability.get("id", hit.get("_id", "unknown-vulnerability"))).upper()
        rule_meta = vulnerability_rules.get(cve_id)

        evidence = [
            f"Package: {package_name} {package_version}",
            f"CVE: {cve_id}",
        ]
        if package.get("architecture"):
            evidence.append(f"Architecture: {package['architecture']}")
        if package.get("type"):
            evidence.append(f"Package type: {package['type']}")
        if vulnerability.get("severity"):
            evidence.append(f"Severity: {vulnerability['severity']}")
        cvss = {}
        if vulnerability.get("score", {}).get("base") is not None:
            cvss["base_score"] = vulnerability["score"]["base"]
            evidence.append(f"CVSS base: {vulnerability['score']['base']}")
        elif rule_meta and rule_meta["cvss"].get("base_score") is not None:
            cvss["base_score"] = rule_meta["cvss"]["base_score"]
            evidence.append(f"CVSS base: {rule_meta['cvss']['base_score']}")
        if vulnerability.get("score", {}).get("vector"):
            cvss["vector"] = vulnerability["score"]["vector"]
        elif rule_meta and rule_meta["cvss"].get("vector"):
            cvss["vector"] = rule_meta["cvss"]["vector"]
        if vulnerability.get("score", {}).get("version"):
            cvss["version"] = str(vulnerability["score"]["version"])
        if vulnerability.get("published_at"):
            evidence.append(f"Published: {vulnerability['published_at']}")
        if vulnerability.get("detected_at"):
            evidence.append(f"Detected: {vulnerability['detected_at']}")
        if vulnerability.get("classification"):
            evidence.append(f"Classification: {vulnerability['classification']}")
        if scanner.get("condition"):
            evidence.append(f"Scanner condition: {scanner['condition']}")

        references = split_references(vulnerability.get("reference"))
        if scanner.get("reference"):
            references.append(str(scanner["reference"]))
        severity = normalize_severity(vulnerability.get("severity") or (rule_meta or {}).get("severity"))
        if not vulnerability.get("severity") and cvss.get("base_score") is not None:
            severity = cvss_severity(float(cvss["base_score"]))
        structured_vulnerability = {
            "_index": hit.get("_index"),
            "_id": hit.get("_id"),
            "agent": dict(agent),
            "host": {"os": dict(host_os)},
            "package": dict(package),
            "vulnerability": dict(vulnerability),
        }

        finding = {
            "host": host,
            "source": "wazuh-indexer-vulnerabilities",
            "category": "vulnerability",
            "rule_id": vulnerability_rule_id(cve_id, package_name),
            "title": vulnerability_title(cve_id, package),
            "severity": severity,
            "status": "fail",
            "evidence": evidence,
            "remediation": vulnerability_remediation(package_name, cve_id, scanner, rule_meta),
            "finding_type": "software_vulnerability",
            "external_ids": {"cve": cve_id},
            "vulnerability_id": cve_id,
            "cve": cve_id,
            "affected_component": {
                "name": package_name,
                "package": package_name,
                "version": package_version,
                "architecture": package.get("architecture"),
                "description": package.get("description"),
                "size": package.get("size"),
                "type": package.get("type"),
            },
            "description": vulnerability.get("description"),
            "detected_at": vulnerability.get("detected_at"),
            "os_platform": host_os.get("full") or host_os.get("platform"),
            "detection_method": vulnerability_detection_method(scanner),
            "references": references,
            "wazuh_vulnerability": structured_vulnerability,
        }
        if cvss:
            finding["cvss"] = cvss
        findings.append(finding)
    return findings


def build_vulnerability_pass_findings(targets, vulnerability_rules, failed_findings):
    failed_keys = {
        (finding["host"], finding["rule_id"])
        for finding in failed_findings
        if finding.get("status") == "fail"
    }
    findings = []
    for host in targets:
        for rule_meta in vulnerability_rules.values():
            if (host, rule_meta["rule_id"]) in failed_keys:
                continue

            packages = sorted(rule_meta["packages"])
            evidence = [
                f"CVE: {rule_meta['cve']}",
                "No matching Wazuh vulnerability state found for this host and rule.",
            ]
            if rule_meta["cvss"].get("base_score") is not None:
                evidence.append(f"CVSS base: {rule_meta['cvss']['base_score']}")
            if packages:
                evidence.append(f"Package: {', '.join(packages)}")

            affected_component = {}
            if packages:
                affected_component["package"] = ", ".join(packages)

            finding = {
                "host": host,
                "source": "wazuh-indexer-vulnerabilities",
                "category": "vulnerability",
                "rule_id": rule_meta["rule_id"],
                "title": rule_meta["title"],
                "severity": rule_meta["severity"],
                "status": "pass",
                "evidence": evidence,
                "remediation": rule_meta["remediation"],
                "finding_type": "software_vulnerability",
                "external_ids": {"cve": rule_meta["cve"]},
                "cve": rule_meta["cve"],
            }
            if rule_meta["cvss"]:
                finding["cvss"] = rule_meta["cvss"]
            if affected_component:
                finding["affected_component"] = affected_component
            findings.append(finding)
    return findings


def main():
    parser = argparse.ArgumentParser(description="Export normalized findings from the Wazuh API.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--raw-alerts-output", default=str(DEFAULT_ALERTS_OUTPUT))
    parser.add_argument("--raw-vulns-output", default=str(DEFAULT_VULNS_OUTPUT))
    parser.add_argument("--hosts", default=",".join(DEFAULT_TARGETS))
    args = parser.parse_args()
    targets = parse_hosts(args.hosts)
    sca_rules, vulnerability_rules = load_profile()

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
            vulnerability_hits, vulnerability_response = fetch_vulnerabilities(indexer, targets, vulnerability_rules)
        except HTTPError as exc:
            raise RuntimeError(f"Failed to query Wazuh indexer vulnerability data: HTTP {exc.code}") from exc
        raw_vulnerabilities["indexer"] = vulnerability_response
        vulnerability_findings = normalize_vulnerability_findings(vulnerability_hits, targets, vulnerability_rules)
        findings.extend(vulnerability_findings)

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
