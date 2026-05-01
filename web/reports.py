import re
import importlib.util
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from fastapi.templating import Jinja2Templates
except ModuleNotFoundError:
    from jinja2 import Environment, FileSystemLoader

    class Jinja2Templates:
        def __init__(self, directory: str):
            self.env = Environment(loader=FileSystemLoader(directory), autoescape=True)

        def get_template(self, name: str):
            return self.env.get_template(name)

from web import runs
from web.filters import apply_filters, normalize_findings


templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def report_generator_module():
    spec = importlib.util.spec_from_file_location("generate_report", PROJECT_ROOT / "scripts" / "generate-report.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9а-яА-ЯёЁ._-]+", "-", value.strip()).strip("-").lower()
    return slug or "export"


def unique_export_id(run_id: str, base: str) -> str:
    exports_dir = runs.run_dir(run_id) / "exports"
    candidate = slugify(base)
    if not (exports_dir / candidate).exists():
        return candidate
    index = 2
    while (exports_dir / f"{candidate}-{index}").exists():
        index += 1
    return f"{candidate}-{index}"


def summary_for(findings: list[dict[str, Any]]) -> dict[str, int]:
    return runs.summarize_findings(findings)


def human_filter_text(filters: dict[str, Any]) -> str:
    if not filters:
        return "Фильтры отчёта не применялись. В отчёт включены все результаты проверки."
    labels = {
        "status": "статус",
        "severity": "уровень опасности",
        "category": "категория",
        "source": "источник",
        "host": "хост",
        "rule_id": "rule_id",
        "title": "название",
        "cve": "CVE",
        "package": "пакет",
        "cvss_base_score": "CVSS",
    }
    ops = {"in": "=", "eq": "=", "contains": "содержит", "gte": ">=", "lte": "<=", "between": "между"}
    parts = []
    for field, spec in filters.items():
        if not spec:
            continue
        value = spec.get("value")
        if isinstance(value, list):
            rendered = " - ".join(str(item) for item in value) if spec.get("op") == "between" else ", ".join(str(item) for item in value)
        else:
            rendered = str(value)
        parts.append(f"{labels.get(field, field)} {ops.get(spec.get('op'), spec.get('op'))} {rendered}")
    return "Применённые фильтры: " + "; ".join(parts) + "."


def create_export(run_id: str, title: str, filters: dict[str, Any], export_id: str | None = None) -> dict[str, Any]:
    metadata = runs.load_metadata(run_id)
    source_findings = normalize_findings(runs.load_findings(run_id))
    filtered = apply_filters(source_findings, filters)
    export_id = unique_export_id(run_id, export_id or title)
    export_dir = runs.run_dir(run_id) / "exports" / export_id
    export_dir.mkdir(parents=True, exist_ok=False)
    export = {
        "id": export_id,
        "title": title,
        "created_at": runs.now_iso(),
        "formats": ["html", "pdf"],
        "filters": filters,
        "result_summary": {
            "total_findings_before_filter": len(source_findings),
            "total_findings_after_filter": len(filtered),
            **summary_for(filtered),
        },
        "files": {"html": "report.html", "pdf": "report.pdf"},
    }
    html_path = export_dir / "report.html"
    html_path.write_text(render_report_html(metadata, export, source_findings, filtered), encoding="utf-8")
    render_pdf(html_path, export_dir / "report.pdf")
    runs.write_json(export_dir / "export.json", export)
    exports = [item for item in runs.list_exports(run_id) if item.get("id") != export_id]
    exports.append(export)
    runs.save_exports_index(run_id, sorted(exports, key=lambda item: item.get("created_at", ""), reverse=True))
    return export


def render_report_html(
    metadata: dict[str, Any],
    export: dict[str, Any],
    all_findings: list[dict[str, Any]],
    filtered_findings: list[dict[str, Any]],
) -> str:
    generator = report_generator_module()
    profile = generator.load_profile(generator.DEFAULT_PROFILE)
    enrichment = generator.load_enrichment(generator.DEFAULT_ENRICHMENT)
    profile_index = generator.build_profile_index(profile, enrichment)
    passports = generator.build_passports(filtered_findings, profile_index, metadata, datetime.now().astimezone())
    template = templates.get_template("report_print.html")
    return template.render(
        request=None,
        metadata=metadata,
        export=export,
        before_summary=summary_for(all_findings),
        findings=filtered_findings,
        passports=passports,
        filter_text=human_filter_text(export.get("filters") or {}),
    )


def render_pdf(html_path: Path, pdf_path: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
        page.pdf(
            path=str(pdf_path),
            format="A4",
            print_background=True,
            margin={"top": "14mm", "right": "14mm", "bottom": "14mm", "left": "14mm"},
        )
        browser.close()
