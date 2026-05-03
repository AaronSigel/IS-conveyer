from __future__ import annotations

import pathlib
import re
from functools import lru_cache
from typing import Any

import yaml


DEFAULT_MAPPING = pathlib.Path(__file__).resolve().parents[1] / "config" / "subsystem_mapping.yaml"


@lru_cache(maxsize=4)
def load_mapping(path: str | None = None) -> dict[str, list[str]]:
    mapping_path = pathlib.Path(path) if path else DEFAULT_MAPPING
    if not mapping_path.exists():
        return {}
    data = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {}
    return {str(key): [str(item) for item in value or []] for key, value in data.items()}


def classify_subsystem(text: Any, mapping_path: str | None = None) -> str:
    haystack = str(text or "").lower()
    for subsystem, patterns in load_mapping(mapping_path).items():
        for pattern in patterns:
            if re.search(re.escape(pattern.lower()), haystack):
                return subsystem
    return "other"
