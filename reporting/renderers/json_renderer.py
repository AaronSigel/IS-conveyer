from __future__ import annotations

import json
import pathlib
from typing import Any


def render_json(report: dict[str, Any], output_path: str | pathlib.Path) -> None:
    """Save normalized report JSON."""
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
