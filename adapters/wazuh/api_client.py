from __future__ import annotations

import base64
import json
import ssl
import urllib.parse
import urllib.request
from typing import Any


class WazuhApiClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.context = ssl._create_unverified_context()
        self.token = self._authenticate()

    def _request(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None, auth: tuple[str, str] | None = None) -> str:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        headers: dict[str, str] = {}
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

    def _authenticate(self) -> str:
        raw = self._request(
            "POST",
            "/security/user/authenticate",
            params={"raw": "true"},
            auth=(self.username, self.password),
        )
        return raw.strip()

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{path}" + (f"?{urllib.parse.urlencode(params, doseq=True)}" if params else ""),
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        with urllib.request.urlopen(request, context=self.context) as response:
            return json.loads(response.read().decode("utf-8"))


def build_inventory_lookup(client: WazuhApiClient, targets: tuple[str, ...]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    response = client.get(
        "/agents",
        params={"select": "id,name,status,ip,lastKeepAlive,version", "limit": 100},
    )
    items = response.get("data", {}).get("affected_items", [])
    return {item["name"]: item for item in items if item.get("name") in targets}, response


def fetch_sca_checks(client: WazuhApiClient, agent_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    response = client.get(f"/sca/{agent_id}/checks/cis_ubuntu24-04", params={"limit": 1000})
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_os(client: WazuhApiClient, agent_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    response = client.get(f"/syscollector/{agent_id}/os")
    return response.get("data", {}).get("affected_items", []), response


def fetch_syscollector_packages(client: WazuhApiClient, agent_id: str, package_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    response = client.get(f"/syscollector/{agent_id}/packages", params={"search": package_name, "limit": 20})
    return response.get("data", {}).get("affected_items", []), response
