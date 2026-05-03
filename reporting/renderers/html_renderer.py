from __future__ import annotations

import json
import pathlib
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


TEMPLATES_DIR = pathlib.Path(__file__).resolve().parents[1] / "templates"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def render_html(report: dict[str, Any], output_path: str | pathlib.Path) -> None:
    """Render technical HTML report."""
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_string(report), encoding="utf-8")


def render_html_string(report: dict[str, Any]) -> str:
    """Render technical HTML report to a string."""
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html", "xml"]))
    env.filters["json"] = _json
    template = env.get_template("technical_report.html")
    return template.render(report=report)
