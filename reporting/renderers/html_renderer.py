from __future__ import annotations

import json
import pathlib
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reporting.i18n import install_jinja_filters


TEMPLATES_DIR = pathlib.Path(__file__).resolve().parents[1] / "templates"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _environment() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html", "xml"]))
    env.filters["json"] = _json
    install_jinja_filters(env)
    return env


def render_html(report: dict[str, Any], output_path: str | pathlib.Path) -> None:
    """Render technical HTML report."""
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_string(report), encoding="utf-8")


def render_html_string(report: dict[str, Any]) -> str:
    """Render technical HTML report to a string."""
    env = _environment()
    template = env.get_template("technical_report.html")
    return template.render(report=report)


def render_passport_registry_html(report: dict[str, Any], output_path: str | pathlib.Path) -> None:
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    env = _environment()
    template = env.get_template("passport_registry.html")
    path.write_text(template.render(report=report), encoding="utf-8")
