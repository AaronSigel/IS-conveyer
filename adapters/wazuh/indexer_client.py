from __future__ import annotations

import base64
import json
import os
import pathlib
import ssl
import subprocess
import urllib.request
from urllib.error import URLError
from typing import Any

from config.runtime import default_vagrant_private_key


def _is_wsl() -> bool:
    try:
        return "microsoft" in pathlib.Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def _manager_ssh_host_port(manager_ip: str | None) -> tuple[str, int | None]:
    override_host = (os.environ.get("WAZUH_MANAGER_SSH_HOST") or "").strip()
    override_port = (os.environ.get("WAZUH_MANAGER_SSH_PORT") or "").strip()
    if override_host:
        return override_host, int(override_port) if override_port else 22

    if manager_ip and _is_wsl() and manager_ip.startswith("192.168.56."):
        return "127.0.0.1", 2222

    return manager_ip or "127.0.0.1", None


class WazuhIndexerClient:
    def __init__(self, base_url: str, username: str, password: str, *, manager_ip: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.manager_ip = manager_ip
        self.context = ssl._create_unverified_context()

    def search(self, index_pattern: str, body: dict[str, Any]) -> dict[str, Any]:
        credentials = f"{self.username}:{self.password}".encode("utf-8")
        encoded = base64.b64encode(credentials).decode("ascii")
        request = urllib.request.Request(
            f"{self.base_url}/{index_pattern}/_search",
            headers={"Authorization": f"Basic {encoded}", "Content-Type": "application/json"},
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

    def _search_via_ssh(self, index_pattern: str, body: dict[str, Any]) -> dict[str, Any]:
        host, port = _manager_ssh_host_port(self.manager_ip)
        command = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
            str(pathlib.Path(default_vagrant_private_key()).expanduser()),
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


def fetch_vulnerabilities(indexer: WazuhIndexerClient, hosts: tuple[str, ...]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    page_size = 500
    collected_hits: list[dict[str, Any]] = []
    total = None
    pages = 0
    search_after = None

    while True:
        body: dict[str, Any] = {
            "size": page_size,
            "sort": [
                {"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}},
                {"vulnerability.id": {"order": "asc", "unmapped_type": "keyword"}},
                {"_id": {"order": "asc"}},
            ],
            "query": {"bool": {"filter": [{"terms": {"agent.name": list(hosts)}}]}},
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
