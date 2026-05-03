from __future__ import annotations

from typing import Any

from reporting.common import UNKNOWN, as_text, first_value, nested


def _affected_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        data = value.get("data") if isinstance(value.get("data"), dict) else value
        items = data.get("affected_items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        if any(key in data for key in ("id", "name", "os")):
            return [data]
    return []


def _agent_record(agent: dict[str, Any]) -> dict[str, Any]:
    labels = agent.get("labels")
    if isinstance(labels, dict):
        labels = [f"{key}={value}" for key, value in labels.items()]
    return {
        "agent.id": as_text(agent.get("id")),
        "agent.name": as_text(agent.get("name")),
        "agent.version": as_text(first_value(agent.get("version"), agent.get("agent_version"))),
        "agent.ip": as_text(first_value(agent.get("ip"), agent.get("registerIP"))),
        "agent.status": as_text(agent.get("status")),
        "agent.labels": labels if isinstance(labels, list) else [],
    }


def _os_record(os_info: dict[str, Any]) -> dict[str, Any]:
    os_data = os_info.get("os") if isinstance(os_info.get("os"), dict) else os_info
    return {
        "host.os.full": as_text(first_value(os_data.get("full"), os_data.get("name"))),
        "host.os.version": as_text(os_data.get("version")),
        "host.os.kernel": as_text(os_data.get("kernel")),
        "host.architecture": as_text(first_value(os_data.get("architecture"), os_data.get("arch"), os_info.get("architecture"))),
    }


def _merge_known(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if value in (None, "", UNKNOWN, []):
            continue
        if target.get(key) in (None, "", UNKNOWN, []):
            target[key] = value


def normalize_asset_enrichment(enrichment: Any) -> dict[str, dict[str, Any]]:
    """Normalize Wazuh /agents and /syscollector/{agent_id}/os data by asset name.

    The function accepts both raw Wazuh API responses and already compact
    dictionaries. Findings remain a fallback source, not the primary inventory
    source, when this data is available.
    """
    if not isinstance(enrichment, dict):
        return {}

    assets: dict[str, dict[str, Any]] = {}
    agents_by_id: dict[str, str] = {}

    for agent in _affected_items(enrichment.get("agents")):
        record = _agent_record(agent)
        name = record.get("agent.name")
        if name == UNKNOWN:
            continue
        asset = assets.setdefault(name, {"agent.name": name})
        _merge_known(asset, record)
        agent_id = record.get("agent.id")
        if agent_id != UNKNOWN:
            agents_by_id[agent_id] = name

    for item in _affected_items(enrichment.get("assets")):
        record = _agent_record(item)
        record.update(_os_record(item))
        name = as_text(first_value(item.get("agent.name"), item.get("name"), record.get("agent.name")))
        if name == UNKNOWN:
            continue
        asset = assets.setdefault(name, {"agent.name": name})
        _merge_known(asset, record)

    syscollector_os = enrichment.get("syscollector_os") or enrichment.get("syscollector") or {}
    if isinstance(syscollector_os, dict):
        iterable = syscollector_os.items()
    else:
        iterable = []
    for key, value in iterable:
        items = _affected_items(value)
        if not items and isinstance(value, dict):
            items = [value]
        asset_name = agents_by_id.get(str(key), str(key))
        for item in items:
            agent_id = as_text(first_value(item.get("agent_id"), nested(item, "agent", "id")), default="")
            name = as_text(first_value(nested(item, "agent", "name"), agents_by_id.get(agent_id), asset_name))
            if name == UNKNOWN:
                continue
            asset = assets.setdefault(name, {"agent.name": name})
            _merge_known(asset, _os_record(item))

    return assets
