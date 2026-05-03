from __future__ import annotations

import hashlib
import json
import re
from typing import Any


UNKNOWN = "unknown"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": -1, "-": -1}


def nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_value(*values: Any, default: str = UNKNOWN) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if value == []:
            continue
        return value
    return default


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_text(value: Any, default: str = UNKNOWN) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    if severity in {"informational", "none", "-", "n/a", "not provided"}:
        return "info"
    return severity or "info"


def severity_rank(value: Any) -> int:
    return SEVERITY_ORDER.get(str(value or "").lower(), -1)


def score_to_severity(score: Any, fallback: Any = None) -> str:
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return normalize_severity(fallback)
    if numeric < 0:
        return "info"
    if numeric >= 9.0:
        return "critical"
    if numeric >= 7.0:
        return "high"
    if numeric >= 4.0:
        return "medium"
    if numeric > 0:
        return "low"
    return "info"


def stable_id(prefix: str, *parts: Any) -> str:
    cleaned = [re.sub(r"[^A-Za-z0-9._-]+", "-", str(part or UNKNOWN)).strip("-") for part in parts]
    base = "-".join(part for part in cleaned if part)[:100]
    digest = hashlib.sha1(json.dumps(parts, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{base}-{digest}" if base else f"{prefix}-{digest}"


def unique_sorted(values: list[Any]) -> list[str]:
    return sorted({str(value) for value in values if value not in (None, "")})


def split_reference_text(value: Any) -> list[str]:
    refs: list[str] = []
    for item in ensure_list(value):
        for part in re.split(r"[\s,]+", str(item or "")):
            if part.startswith("http://") or part.startswith("https://"):
                refs.append(part.strip().rstrip(".,;"))
    return unique_sorted(refs)


def evidence_text(finding: dict[str, Any]) -> str:
    parts = [finding.get("title"), finding.get("description"), finding.get("impact")]
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        parts.extend(evidence)
    return " ".join(str(part or "") for part in parts).lower()
