#!/usr/bin/env python3
import argparse
import base64
import json
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
CREDS_PATH = ARTIFACTS_DIR / "wazuh-credentials.env"
INVENTORY_PATH = PROJECT_ROOT / "ansible" / "inventory" / "hosts.ini"
DEFAULT_TARGETS = ("target1", "target2")
SCA_POLICY_ID = "host-baseline-v1"


def parse_hosts(raw_hosts):
    hosts = tuple(host.strip() for host in raw_hosts.split(",") if host.strip())
    if not hosts:
        raise ValueError("At least one host must be provided")
    return hosts


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


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
        request = urllib.request.Request(url, method=method, headers=headers)
        if auth:
            credentials = f"{auth[0]}:{auth[1]}".encode("utf-8")
            encoded = base64.b64encode(credentials).decode("ascii")
            request.add_header("Authorization", f"Basic {encoded}")
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


def run_command(command):
    result = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}\n{result.stderr}".strip()
        )
    return result


def agent_inventory(client, hosts):
    response = client.get("/agents", params={"select": "id,name,status,lastKeepAlive", "limit": 100})
    items = response.get("data", {}).get("affected_items", [])
    return {item["name"]: item for item in items if item.get("name") in hosts}


def sca_ready(client, agent_id):
    response = client.get(f"/sca/{agent_id}/checks/{SCA_POLICY_ID}", params={"limit": 100})
    items = response.get("data", {}).get("affected_items", [])
    return len(items) > 0


def syscollector_packages_ready(client, agent_id):
    response = client.get(f"/syscollector/{agent_id}/packages", params={"limit": 1})
    items = response.get("data", {}).get("affected_items", [])
    return len(items) > 0


def wait_for_scan_data(client, hosts, timeout, interval):
    deadline = time.time() + timeout
    pending = set(hosts)

    while pending and time.time() < deadline:
        inventory = agent_inventory(client, hosts)
        still_pending = set()

        for host in pending:
            agent = inventory.get(host)
            if not agent or agent.get("status") != "active" or not agent.get("id"):
                still_pending.add(host)
                continue

            agent_id = agent["id"]
            if not sca_ready(client, agent_id):
                still_pending.add(host)
                continue
            if not syscollector_packages_ready(client, agent_id):
                still_pending.add(host)
                continue

        pending = still_pending
        if pending:
            time.sleep(interval)

    if pending:
        raise RuntimeError(f"Timed out waiting for scan data for: {', '.join(sorted(pending))}")


def build_output_paths(prefix):
    if not prefix:
        return (
            ARTIFACTS_DIR / "unified-findings.json",
            ARTIFACTS_DIR / "raw-wazuh-alerts.json",
            ARTIFACTS_DIR / "raw-wazuh-vulnerabilities.json",
            ARTIFACTS_DIR / "draft-report.md",
        )

    normalized = prefix.strip().strip("-")
    if not normalized:
        raise ValueError("Output prefix must not be empty")
    return (
        ARTIFACTS_DIR / f"{normalized}-unified-findings.json",
        ARTIFACTS_DIR / f"{normalized}-raw-wazuh-alerts.json",
        ARTIFACTS_DIR / f"{normalized}-raw-wazuh-vulnerabilities.json",
        ARTIFACTS_DIR / f"{normalized}-draft-report.md",
    )


def main():
    parser = argparse.ArgumentParser(description="Trigger host scans and produce vulnerability reports.")
    parser.add_argument("--hosts", default=",".join(DEFAULT_TARGETS), help="Comma-separated inventory hostnames.")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum wait time for scan data in seconds.")
    parser.add_argument("--poll-interval", type=int, default=15, help="Polling interval in seconds.")
    parser.add_argument("--output-prefix", default="", help="Optional prefix for generated artifacts.")
    args = parser.parse_args()

    hosts = parse_hosts(args.hosts)
    creds = load_env_file(CREDS_PATH)
    required = ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
    missing = [key for key in required if not creds.get(key)]
    if missing:
        raise RuntimeError(f"Missing Wazuh API credentials: {', '.join(missing)}")

    print(f"scan started at {iso_now()}")
    print(f"hosts: {', '.join(hosts)}")

    limit = ":".join(hosts)
    run_command(
        [
            "ansible",
            limit,
            "-i",
            str(INVENTORY_PATH),
            "-b",
            "-m",
            "systemd",
            "-a",
            "name=wazuh-agent state=restarted",
        ]
    )

    client = WazuhApiClient(
        creds["WAZUH_API_URL"],
        creds["WAZUH_API_USER"],
        creds["WAZUH_API_PASSWORD"],
    )
    wait_for_scan_data(client, hosts, args.timeout, args.poll_interval)

    unified_path, raw_alerts_path, raw_vulns_path, report_path = build_output_paths(args.output_prefix)

    run_command(
        [
            "python3",
            "scripts/export-findings.py",
            "--hosts",
            ",".join(hosts),
            "--output",
            str(unified_path),
            "--raw-alerts-output",
            str(raw_alerts_path),
            "--raw-vulns-output",
            str(raw_vulns_path),
        ]
    )
    run_command(
        [
            "python3",
            "scripts/generate-report.py",
            "--input",
            str(unified_path),
            "--output",
            str(report_path),
        ]
    )

    print(f"unified findings: {unified_path}")
    print(f"raw alerts: {raw_alerts_path}")
    print(f"raw vulnerabilities: {raw_vulns_path}")
    print(f"report: {report_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"run-host-scan.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
