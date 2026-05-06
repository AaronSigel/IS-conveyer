import re
from datetime import datetime
from pathlib import Path
from typing import Any

from reporting.renderers import render_pdf as render_technical_pdf
from reporting.renderers import render_json as render_technical_json
from reporting.renderers.html_renderer import render_html_string as render_technical_html_string
from reporting.services.report_export import (
    DEFAULT_ENRICHMENT,
    DEFAULT_PROFILE,
    build_normalized_report_for_export,
    build_passports,
    build_profile_index,
    load_enrichment,
    load_profile,
)

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
from web.i18n import install_jinja_filters


templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
install_jinja_filters(templates.env)


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


def _with_filter(filters: dict[str, Any], field: str, spec: dict[str, Any]) -> dict[str, Any]:
    merged = dict(filters)
    merged[field] = spec
    return merged


def split_report_specs(base_filters: dict[str, Any], hosts: list[str]) -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    status_filter = base_filters.get("status")
    for host in hosts:
        safe_host = slugify(host)
        host_filter = {"host": {"op": "eq", "value": host}}
        configuration = {
            "finding_type": {"op": "eq", "value": "configuration_noncompliance"},
            **host_filter,
        }
        if status_filter:
            configuration["status"] = status_filter
        packages = _with_filter(dict(base_filters), "host", {"op": "eq", "value": host})
        packages["finding_type"] = {"op": "eq", "value": "software_vulnerability"}
        specs[f"{safe_host}-configuration"] = {
            "title": f"{host} - отчёт по конфигурации",
            "host": host,
            "html": f"{safe_host}-configuration-report.html",
            "pdf": f"{safe_host}-configuration-report.pdf",
            "json": f"{safe_host}-configuration-normalized_report.json",
            "filters": configuration,
        }
        specs[f"{safe_host}-packages"] = {
            "title": f"{host} - отчёт по уязвимостям пакетов",
            "host": host,
            "html": f"{safe_host}-packages-report.html",
            "pdf": f"{safe_host}-packages-report.pdf",
            "json": f"{safe_host}-packages-normalized_report.json",
            "filters": packages,
        }
    return specs


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
        "finding_type": "тип находки",
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


def create_export(
    run_id: str,
    title: str,
    filters: dict[str, Any],
    export_id: str | None = None,
    report_mode: str = "combined",
) -> dict[str, Any]:
    metadata = runs.load_metadata(run_id)
    source_findings = normalize_findings(runs.load_findings(run_id))
    export_id = unique_export_id(run_id, export_id or title)
    export_dir = runs.run_dir(run_id) / "exports" / export_id
    export_dir.mkdir(parents=True, exist_ok=False)
    pdf_errors: list[str] = []
    if report_mode == "split":
        reports = {}
        total_after_filter = 0
        combined_summary = runs.empty_summary()
        combined_assets_by_host: dict[str, list[dict[str, Any]]] = {}
        hosts = [str(host) for host in metadata.get("hosts") or []]
        if not hosts:
            hosts = sorted({str(item.get("host")) for item in source_findings if item.get("host")})
        for report_id, spec in split_report_specs(filters, hosts).items():
            report_filters = spec["filters"]
            filtered = apply_filters(source_findings, report_filters)
            normalized_report = build_normalized_report_for_export(
                source_findings,
                filtered_findings=filtered,
                metadata=metadata,
                profile=metadata.get("profile_id"),
                report_id=report_id,
            )
            host = str(spec.get("host") or "")
            if host and host not in combined_assets_by_host:
                combined_filters = _with_filter(dict(filters), "host", {"op": "eq", "value": host})
                host_filtered = apply_filters(source_findings, combined_filters)
                host_report = build_normalized_report_for_export(
                    source_findings,
                    filtered_findings=host_filtered,
                    metadata=metadata,
                    profile=metadata.get("profile_id"),
                    report_id=f"{host}-combined",
                )
                combined_assets_by_host[host] = host_report.get("assets", [])
            if host and combined_assets_by_host.get(host):
                normalized_report["assets"] = combined_assets_by_host[host]
                normalized_report["scope"] = {"assets": combined_assets_by_host[host]}
            report_export = {
                "id": report_id,
                "title": spec["title"],
                "created_at": runs.now_iso(),
                "filters": report_filters,
                "result_summary": {
                    "total_findings_before_filter": len(source_findings),
                    "total_findings_after_filter": len(filtered),
                    **summary_for(filtered),
                },
            }
            html_path = export_dir / spec["html"]
            pdf_path = export_dir / spec["pdf"]
            json_path = export_dir / spec["json"]
            render_technical_json(normalized_report, json_path)
            html_path.write_text(render_technical_html_string(normalized_report), encoding="utf-8")
            try:
                render_pdf(html_path, pdf_path)
            except Exception as exc:
                pdf_errors.append(f"{report_id}: {exc}")
            files = {"html": spec["html"], "json": spec["json"]}
            if pdf_path.exists():
                files["pdf"] = spec["pdf"]
            reports[report_id] = {
                "id": report_id,
                "title": spec["title"],
                "filters": report_filters,
                "result_summary": report_export["result_summary"],
                "files": files,
            }
            total_after_filter += len(filtered)
            for key, value in summary_for(filtered).items():
                combined_summary[key] = combined_summary.get(key, 0) + value
        export = {
            "id": export_id,
            "title": title,
            "created_at": runs.now_iso(),
            "formats": ["json", "html", "pdf"] if not pdf_errors else ["json", "html"],
            "mode": "split",
            "filters": filters,
            "result_summary": {
                "total_findings_before_filter": len(source_findings),
                "total_findings_after_filter": total_after_filter,
                **combined_summary,
            },
            "reports": reports,
        }
        if pdf_errors:
            export["pdf_errors"] = pdf_errors
        runs.write_json(export_dir / "export.json", export)
        exports = [item for item in runs.list_exports(run_id) if item.get("id") != export_id]
        exports.append(export)
        runs.save_exports_index(run_id, sorted(exports, key=lambda item: item.get("created_at", ""), reverse=True))
        return export

    filtered = apply_filters(source_findings, filters)
    normalized_report = build_normalized_report_for_export(
        source_findings,
        filtered_findings=filtered,
        metadata=metadata,
        profile=metadata.get("profile_id"),
        report_id=export_id,
    )
    export = {
        "id": export_id,
        "title": title,
        "created_at": runs.now_iso(),
        "formats": ["json", "html", "pdf"],
        "filters": filters,
        "result_summary": {
            "total_findings_before_filter": len(source_findings),
            "total_findings_after_filter": len(filtered),
            **summary_for(filtered),
        },
        "files": {"json": "normalized_report.json", "html": "technical_report.html", "pdf": "technical_report.pdf"},
    }
    render_technical_json(normalized_report, export_dir / "normalized_report.json")
    html_path = export_dir / "technical_report.html"
    html_path.write_text(render_technical_html_string(normalized_report), encoding="utf-8")
    pdf_path = export_dir / "technical_report.pdf"
    try:
        render_pdf(html_path, pdf_path)
    except Exception as exc:
        export["formats"] = ["json", "html"]
        export["files"].pop("pdf", None)
        export["pdf_errors"] = [str(exc)]
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
    profile = load_profile(DEFAULT_PROFILE)
    enrichment = load_enrichment(DEFAULT_ENRICHMENT)
    profile_index = build_profile_index(profile, enrichment)
    passports = build_passports(filtered_findings, profile_index, metadata, datetime.now().astimezone())
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
    render_technical_pdf(html_path, pdf_path)
