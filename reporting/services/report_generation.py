from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from reporting import build_normalized_report
from reporting.renderers import render_html as render_technical_html
from reporting.renderers import render_json as render_technical_json
from reporting.renderers import render_pdf as render_technical_pdf
from reporting.services.report_export import build_normalized_report_for_export


def safe_filename_part(value: Any) -> str:
    text = str(value or "host").strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-._")
    return safe or "host"


def metadata_for_host(metadata: dict[str, Any], host: str) -> dict[str, Any]:
    narrowed = dict(metadata)
    stand = dict(metadata.get("stand", {}) or {})
    hosts = stand.get("hosts", []) or []
    if hosts:
        stand["hosts"] = [item for item in hosts if str(item.get("name", "")).lower() == str(host).lower()]
    narrowed["stand"] = stand
    return narrowed


def split_report_hosts(selected_findings: list[dict[str, Any]], metadata: dict[str, Any], filters: dict[str, Any]) -> list[str]:
    if filters.get("host"):
        return sorted({str(host) for host in filters["host"] if str(host).strip()})

    metadata_hosts = metadata.get("stand", {}).get("hosts", []) or []
    checked_hosts = [host for host in metadata_hosts if "проверяем" in str(host.get("role", "")).lower()]
    named_hosts = checked_hosts or metadata_hosts
    host_names = {str(host.get("name")) for host in named_hosts if host.get("name")}
    if host_names:
        return sorted(host_names)

    hosts = {str(item.get("host")) for item in selected_findings if item.get("host")}
    return sorted(hosts)


def technical_output_paths(args: Any, default_output_dir: Path) -> tuple[Path, Path, Path]:
    output_dir = Path(args.output).parent if args.output else default_output_dir
    return (
        Path(args.normalized_output) if args.normalized_output else output_dir / "normalized_report.json",
        Path(args.html_output) if args.html_output else output_dir / "technical_report.html",
        Path(args.pdf_output) if args.pdf_output else output_dir / "technical_report.pdf",
    )


def render_technical_outputs(report: dict[str, Any], json_path: Path, html_path: Path, pdf_path: Path, skip_pdf: bool = False) -> None:
    render_technical_json(report, json_path)
    render_technical_html(report, html_path)
    if not skip_pdf:
        try:
            render_technical_pdf(html_path, pdf_path)
        except Exception as exc:
            print(f"PDF rendering skipped: {exc}", file=sys.stderr)


def render_technical_split_reports(
    args: Any,
    findings: list[dict[str, Any]],
    selected_findings: list[dict[str, Any]],
    metadata: dict[str, Any],
    profile_name: str,
    report_datetime,
    infer_finding_type,
) -> list[Path]:
    if not args.split_output_dir:
        return []
    output_dir = Path(args.split_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for host in split_report_hosts(selected_findings, metadata, {}):
        for kind, finding_type in (("configuration", "configuration_noncompliance"), ("packages", "software_vulnerability")):
            host_findings = [item for item in selected_findings if str(item.get("host")) == str(host)]
            if kind == "packages":
                split_findings = [item for item in host_findings if infer_finding_type(item) == "software_vulnerability"]
            else:
                split_findings = [item for item in host_findings if infer_finding_type(item) != "software_vulnerability"]
            split_report = build_normalized_report_for_export(
                findings,
                filtered_findings=split_findings,
                metadata=metadata_for_host(metadata, host),
                profile=profile_name,
                report_id=f"{host}-{kind}",
                generated_at=report_datetime,
            )
            base = output_dir / f"{safe_filename_part(host)}-{kind}-report"
            render_technical_outputs(split_report, base.with_suffix(".json"), base.with_suffix(".html"), base.with_suffix(".pdf"), args.skip_pdf)
            written.extend([base.with_suffix(".json"), base.with_suffix(".html")])
            if not args.skip_pdf and base.with_suffix(".pdf").exists():
                written.append(base.with_suffix(".pdf"))
    return written
