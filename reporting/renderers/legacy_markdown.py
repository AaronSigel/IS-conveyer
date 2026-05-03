from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader


def markdown_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", "<br>")


def jinja_env(templates_dir: Path) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    env.filters["md"] = markdown_cell
    return env


def render_passport(passport: dict[str, Any], section_number: str, templates_dir: Path, template_name: str) -> str:
    return jinja_env(templates_dir).get_template(template_name).render(passport=passport, section_number=section_number).strip()


def render_report(context: dict[str, Any], output_path: str | Path, templates_dir: Path, report_template: str, passport_template: str) -> None:
    rendered_passports = []
    for index, passport in enumerate(context["passports"], start=1):
        rendered_passports.append(render_passport(passport, f"5.{index}", templates_dir, passport_template))
    payload = dict(context)
    payload["rendered_passports"] = rendered_passports
    report = jinja_env(templates_dir).get_template(report_template).render(**payload)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.rstrip() + "\n", encoding="utf-8")
