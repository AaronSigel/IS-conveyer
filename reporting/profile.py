from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from reporting.services.report_export import load_enrichment, load_profile


def load_yaml_file(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_metadata(path: str | Path | None) -> dict[str, Any]:
    metadata = load_yaml_file(path)
    metadata.setdefault("report", {})
    metadata.setdefault("assessment", {})
    metadata.setdefault("stand", {})
    metadata.setdefault("tools", [])
    return metadata


def load_findings(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Findings file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON array")
    return data
