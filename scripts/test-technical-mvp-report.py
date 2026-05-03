#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import tempfile

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reporting.technical_mvp import ReportOptions, build_technical_report, load_wazuh_findings, render_technical_report


SAMPLE_DIR = PROJECT_ROOT / "report" / "samples" / "wazuh-mvp"


def test_load_and_normalize_directory() -> None:
    raw, appendix = load_wazuh_findings(SAMPLE_DIR)
    assert len(raw) >= 4
    assert appendix
    report = build_technical_report(raw, appendix, ReportOptions(min_severity="medium"))
    assert report["stats"]["hosts_count"] == 2
    assert report["stats"]["unique_cve"] == 1
    assert report["stats"]["by_status"]["pass"] == 1
    assert report["stats"]["configuration_failures"] == 2
    assert report["software_by_host"]["target1"][0]["cve"] == "CVE-2025-32463"
    assert report["configuration_by_host"]["target1"]
    assert any(item["type"] == "уязвимость кода" for item in report["passports"])
    assert any(item["type"] == "уязвимость конфигурации" for item in report["passports"])


def test_filters_and_renderers() -> None:
    raw, appendix = load_wazuh_findings(SAMPLE_DIR)
    report = build_technical_report(raw, appendix, ReportOptions(min_severity="critical", include_passed=False))
    assert report["stats"]["included_findings"] == 1
    assert report["stats"]["dropped"]["severity"] >= 2
    with tempfile.TemporaryDirectory() as tmp:
        md = pathlib.Path(tmp) / "report.md"
        html = pathlib.Path(tmp) / "report.html"
        render_technical_report(report, md, "md")
        render_technical_report(report, html, "html")
        md_text = md.read_text(encoding="utf-8")
        html_text = html.read_text(encoding="utf-8")
        assert "Технический отчёт" in md_text
        assert "Уязвимости установленного программного обеспечения" in md_text
        assert "<html" in html_text
        assert "CVE-2025-32463" in html_text


if __name__ == "__main__":
    test_load_and_normalize_directory()
    test_filters_and_renderers()
    print("technical MVP report tests passed")
