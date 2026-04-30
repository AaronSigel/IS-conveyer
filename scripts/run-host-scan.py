#!/usr/bin/env python3
import argparse
import base64
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from urllib.error import HTTPError


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
    inventory_path = build_runtime_inventory()
    env = {
        **dict(os.environ),
        "ANSIBLE_CONFIG": str(PROJECT_ROOT / "ansible.cfg"),
        "ANSIBLE_ROLES_PATH": str(PROJECT_ROOT / "ansible" / "roles"),
    }
    patched_command = [
        str(inventory_path) if part == str(INVENTORY_PATH) else part
        for part in command
    ]
    try:
        result = subprocess.run(patched_command, cwd=PROJECT_ROOT, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed ({result.returncode}): {' '.join(patched_command)}\n{result.stdout}\n{result.stderr}".strip()
            )
        return result
    finally:
        if inventory_path != INVENTORY_PATH and inventory_path.exists():
            inventory_path.unlink()


def build_runtime_inventory():
    windows_host_ip = os.environ.get("WINDOWS_HOST_IP", "127.0.0.1").strip() or "127.0.0.1"
    if windows_host_ip == "127.0.0.1":
        return INVENTORY_PATH

    inventory_text = INVENTORY_PATH.read_text(encoding="utf-8").replace(
        "ansible_host=127.0.0.1",
        f"ansible_host={windows_host_ip}",
    )
    vagrant_key = os.environ.get("VAGRANT_INSECURE_PRIVATE_KEY") or "~/.vagrant.d/insecure_private_key"
    inventory_text += f"\nansible_ssh_private_key_file={vagrant_key}\n"
    runtime_inventory = ARTIFACTS_DIR / "runtime-hosts.ini"
    runtime_inventory.write_text(inventory_text, encoding="utf-8")
    return runtime_inventory


def command_result(command):
    return subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True)


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
        return None

    normalized = prefix.strip().strip("-")
    if not normalized:
        raise ValueError("Output prefix must not be empty")
    return normalized


def load_required_credentials():
    creds = load_env_file(CREDS_PATH)
    required = ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD")
    missing = [key for key in required if not creds.get(key)]
    if missing:
        raise RuntimeError(f"Missing Wazuh API credentials: {', '.join(missing)}")
    return creds


def build_api_client(creds):
    return WazuhApiClient(
        creds["WAZUH_API_URL"],
        creds["WAZUH_API_USER"],
        creds["WAZUH_API_PASSWORD"],
    )


def main():
    parser = argparse.ArgumentParser(description="Trigger Wazuh host scans and wait for fresh data.")
    parser.add_argument("--hosts", default=",".join(DEFAULT_TARGETS), help="Comma-separated inventory hostnames.")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum wait time for scan data in seconds.")
    parser.add_argument("--poll-interval", type=int, default=15, help="Polling interval in seconds.")
    parser.add_argument(
        "--output-prefix",
        default="",
        help="Optional logical scan label printed on completion. Artifacts are not created by this script.",
    )
    args = parser.parse_args()

    hosts = parse_hosts(args.hosts)

    print(f"scan started at {iso_now()}")
    print(f"hosts: {', '.join(hosts)}")
    creds = load_required_credentials()

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

    try:
        client = build_api_client(creds)
    except HTTPError as exc:
        if exc.code != 401:
            raise
        creds = load_required_credentials()
        client = build_api_client(creds)
    wait_for_scan_data(client, hosts, args.timeout, args.poll_interval)

    scan_label = build_output_paths(args.output_prefix)
    if scan_label:
        print(f"scan label: {scan_label}")
    print("scan data is ready for export")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"run-host-scan.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
