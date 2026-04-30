import re
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates

from web import runs
from web.filters import apply_filters, normalize_findings


templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


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
    template = templates.get_template("report_print.html")
    return template.render(
        request=None,
        metadata=metadata,
        export=export,
        before_summary=summary_for(all_findings),
        findings=filtered_findings,
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
