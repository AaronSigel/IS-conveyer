#!/usr/bin/env python3
import pathlib
import importlib.util
import json
import subprocess
import sys
import tempfile


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATOR = PROJECT_ROOT / "scripts" / "generate-report.py"
SAMPLE_FINDINGS = PROJECT_ROOT / "report" / "samples" / "sample-findings.json"
PROFILE = PROJECT_ROOT / "profiles" / "cis_ubuntu24-04.yml"
METADATA = PROJECT_ROOT / "config" / "report-metadata.yml"
FORBIDDEN = ("РЕФЕРАТ", "СОДЕРЖАНИЕ", "ПРИЛОЖЕНИЯ", "СВОДНАЯ ТАБЛИЦА", "ПЛАН УСТРАНЕНИЯ")


def run_report(output, *extra_args):
    command = [
        sys.executable,
        str(GENERATOR),
        "--mode",
        "legacy",
        "--findings",
        str(SAMPLE_FINDINGS),
        "--profile",
        str(PROFILE),
        "--metadata",
        str(METADATA),
        "--output",
        str(output),
        *extra_args,
    ]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True, capture_output=True, text=True)
    assert output.exists(), f"Report was not created: {output}"
    return output.read_text(encoding="utf-8")


def run_technical_report(tmpdir):
    normalized = tmpdir / "normalized_report.json"
    html = tmpdir / "technical_report.html"
    pdf = tmpdir / "technical_report.pdf"
    registry_json = tmpdir / "passport_registry.json"
    registry_html = tmpdir / "passport_registry.html"
    split_dir = tmpdir / "technical-split"
    command = [
        sys.executable,
        str(GENERATOR),
        "--findings",
        str(SAMPLE_FINDINGS),
        "--profile",
        str(PROFILE),
        "--metadata",
        str(METADATA),
        "--output",
        str(tmpdir / "draft-report.md"),
        "--normalized-output",
        str(normalized),
        "--html-output",
        str(html),
        "--pdf-output",
        str(pdf),
        "--passport-registry-json",
        str(registry_json),
        "--passport-registry-html",
        str(registry_html),
        "--split-output-dir",
        str(split_dir),
        "--skip-pdf",
    ]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True, capture_output=True, text=True)
    assert normalized.exists()
    assert html.exists()
    assert registry_json.exists()
    assert registry_html.exists()
    assert (split_dir / "target1-configuration-report.html").exists()
    assert (split_dir / "target1-packages-report.html").exists()
    assert (split_dir / "target2-configuration-report.html").exists()
    assert (split_dir / "target2-packages-report.html").exists()
    return (
        json.loads(normalized.read_text(encoding="utf-8")),
        html.read_text(encoding="utf-8"),
        json.loads(registry_json.read_text(encoding="utf-8")),
        registry_html.read_text(encoding="utf-8"),
        split_dir,
    )


def assert_sections(report):
    for number in range(0, 7):
        assert f"## {number} " in report, f"Missing section {number}"


def assert_no_forbidden_sections(report):
    upper = report.upper()
    for marker in FORBIDDEN:
        assert marker not in upper, f"Forbidden section found: {marker}"


def assert_passport_format(report, expected_passports):
    assert "Паспорт №" in report
    assert report.count("Паспорт №") == expected_passports
    assert "<th>host</th><th>source</th><th>category</th><th>rule_id</th>" not in report
    assert "| host | source | category | rule_id |" not in report
    assert "Рекомендации/remediation" not in report
    assert "Элемент описания уязвимости" in report
    assert "Описание уязвимости" in report
    assert "Возможные меры по устранению уязвимости" in report


def render_sample_html():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    spec = importlib.util.spec_from_file_location("web_reports", PROJECT_ROOT / "web" / "reports.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    findings = json.loads(SAMPLE_FINDINGS.read_text(encoding="utf-8"))
    filtered = [item for item in findings if item.get("status") == "fail"]
    export = {
        "id": "test",
        "title": "Тестовый экспорт",
        "created_at": "2026-05-01T00:00:00+03:00",
        "filters": {"status": {"op": "in", "value": ["fail"]}},
        "result_summary": {"total_findings_after_filter": len(filtered), "fail": len(filtered), "high": 1},
    }
    metadata = {"id": "run-test", "status": "completed", "hosts": ["target1"], "profile_id": "cis_ubuntu24-04"}
    return module.render_report_html(metadata, export, findings, module.normalize_findings(filtered))


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)

        full_report = run_report(tmpdir / "full.md")
        assert_sections(full_report)
        assert_no_forbidden_sections(full_report)
        assert full_report.count("### 5.") == 4, "Expected one passport per sample finding"
        assert_passport_format(full_report, 4)
        assert "| Критерии опасности уязвимости | 9.3" in full_report
        assert "| Степень опасности уязвимости | critical |" in full_report
        assert "| ID | 35500 |" in full_report
        assert "| Title | 1.1.1.1 Ensure cramfs kernel module is not available (Automated) |" in full_report
        assert "| Target | modprobe -n -v cramfs |" in full_report
        assert "| Result | failed |" in full_report
        assert "| Rationale | Disabling uncommon filesystems reduces the kernel attack surface. |" in full_report
        assert "| Remediation | Edit or create a file in `/etc/modprobe.d/` ending in `.conf` and add `install cramfs /bin/false`. |" in full_report
        assert "| Description | The cramfs filesystem type is not commonly used and should be disabled. |" in full_report
        assert "| Checks | c:modprobe -n -v cramfs -> r:^install /bin/false |" in full_report
        assert "| iso_27001-2013 | 1.1.6,1.2.1,2.2.2,2.2.5 |" in full_report

        split_dir = tmpdir / "split"
        run_report(tmpdir / "split-source.md", "--split-output-dir", str(split_dir))
        target1_configuration = split_dir / "target1-configuration-report.md"
        target1_packages = split_dir / "target1-packages-report.md"
        target2_configuration = split_dir / "target2-configuration-report.md"
        target2_packages = split_dir / "target2-packages-report.md"
        for report_path in (target1_configuration, target1_packages, target2_configuration, target2_packages):
            assert report_path.exists(), f"Split report was not created: {report_path}"

        target1_configuration_report = target1_configuration.read_text(encoding="utf-8")
        assert "Ensure cramfs kernel module is not available" in target1_configuration_report
        assert "Ensure X11 forwarding is disabled" in target1_configuration_report
        assert "Sudo chroot option" not in target1_configuration_report
        assert target1_configuration_report.count("### 5.") == 2

        target1_packages_report = target1_packages.read_text(encoding="utf-8")
        assert "Sudo chroot option" in target1_packages_report
        assert "CVE-2025-32463" in target1_packages_report
        assert "| Наименование ПО и его версия | sudo 1.9.15p5-3ubuntu5 |" in target1_packages_report
        assert "| agent.version | v4.14.5 |" in target1_packages_report
        assert "| host.os.kernel | 6.8.0-106-generic |" in target1_packages_report
        assert "| package.architecture | amd64 |" in target1_packages_report
        assert "| vulnerability.scanner.condition | Package less than 1.9.15p5-3ubuntu5.24.04.1 |" in target1_packages_report
        assert "Ensure cramfs kernel module is not available" not in target1_packages_report
        assert target1_packages_report.count("### 5.") == 1

        target2_configuration_report = target2_configuration.read_text(encoding="utf-8")
        assert "Ensure auditd is installed" in target2_configuration_report
        assert "Sudo chroot option" not in target2_configuration_report
        assert target2_configuration_report.count("### 5.") == 1

        target2_packages_report = target2_packages.read_text(encoding="utf-8")
        assert "По заданным критериям фильтрации уязвимости и несоответствия не выявлены." in target2_packages_report
        assert "### 5." not in target2_packages_report

        high_report = run_report(tmpdir / "high.md", "--severity", "high")
        assert "Ensure cramfs kernel module is not available" in high_report
        assert "Ensure X11 forwarding is disabled" not in high_report
        assert "Sudo chroot option" not in high_report
        assert high_report.count("### 5.") == 1

        failed_report = run_report(tmpdir / "failed.md", "--status", "failed")
        assert "Ensure auditd is installed" not in failed_report
        assert failed_report.count("### 5.") == 3
        assert_passport_format(failed_report, 3)
        assert "Применённые фильтры: статус = fail." in failed_report

        cvss_report = run_report(tmpdir / "cvss.md", "--source", "wazuh_vulnerability", "--cvss-min", "5.0")
        assert "Sudo chroot option" in cvss_report
        assert "Запрет входа root по SSH" not in cvss_report
        assert cvss_report.count("### 5.") == 1

        empty_report = run_report(tmpdir / "empty.md", "--severity", "low", "--status", "failed")
        assert "По заданным критериям фильтрации уязвимости и несоответствия не выявлены." in empty_report
        assert "### 5." not in empty_report

        html_report = render_sample_html()
        assert_passport_format(html_report, 3)
        assert "Применённые фильтры: статус = fail." in html_report
        assert "{'status': {'op': 'in'" not in html_report
        assert "<th>Элемент описания уязвимости</th><th>Описание уязвимости</th>" in html_report
        assert "<td>ID</td><td>35500</td>" in html_report
        assert "<td>Target</td><td>modprobe -n -v cramfs</td>" in html_report
        assert "<td>Result</td><td>failed</td>" in html_report
        assert "<td>Checks</td><td>c:modprobe -n -v cramfs -&gt; r:^install /bin/false</td>" in html_report
        assert "<td>iso_27001-2013</td><td>1.1.6,1.2.1,2.2.2,2.2.5</td>" in html_report
        assert "<td>agent.version</td><td>v4.14.5</td>" in html_report
        assert "<td>package.architecture</td><td>amd64</td>" in html_report
        assert "<td>vulnerability.scanner.source</td><td>Canonical Security Tracker</td>" in html_report

        normalized, technical_html, registry_json, registry_html, technical_split_dir = run_technical_report(tmpdir)
        assert normalized["summary"]["raw_findings"] == 4
        assert normalized["summary"]["unique_findings"] == 4
        assert normalized["scope"]["assets"]
        assert normalized["findings"]
        assert normalized["remediation_plan"]
        assert normalized["vulnerability_passports"]
        assert normalized["passport_matrix"]
        assert any(passport["vulnerability_class"] == "уязвимость кода" for passport in normalized["vulnerability_passports"])
        assert any(passport["vulnerability_class"] == "уязвимость конфигурации" for passport in normalized["vulnerability_passports"])
        assert all(passport["passport_completeness_score"] >= 0.9 for passport in normalized["summary_passports"])
        assert len([passport for passport in normalized["summary_passports"] if passport["passport_type"] in {"software", "software_group"}]) <= 10
        assert len(normalized["summary_remediation_plan"]) <= 16
        assert normalized["summary_verification_checklist"]
        assert "Приоритетный план устранения" in technical_html
        assert "Порядок проверки устранения" in technical_html
        assert "Матрица соответствия структуре паспорта уязвимости" in technical_html
        assert "Паспорта ключевых уязвимостей и несоответствий" in technical_html
        assert "PKG-CVE-" not in technical_html
        assert "No main findings for the selected filters" not in technical_html
        assert "Command output matches the remediation target" not in technical_html
        assert "Package default status" not in technical_html
        assert "Raw expected state" not in technical_html
        assert "Уязвимость CVE-2025-32463 в пакете sudo" in technical_html
        assert registry_json == normalized["vulnerability_passports"]
        assert "Реестр паспортов уязвимостей" in registry_html
        assert "Raw expected state" in registry_html
        assert "Full normalized JSON" not in technical_html
        assert "Appendix A. Raw Wazuh fields" not in technical_html
        assert "{{ report|json }}" not in technical_html
        main_before_appendix = technical_html.split("Appendix A. Raw Wazuh fields", 1)[0]
        assert "_index" not in main_before_appendix
        assert "package.size" not in main_before_appendix

        quality_spec = importlib.util.spec_from_file_location("report_quality_check", PROJECT_ROOT / "scripts" / "report_quality_check.py")
        quality = importlib.util.module_from_spec(quality_spec)
        assert quality_spec and quality_spec.loader
        quality_spec.loader.exec_module(quality)
        failures = quality.check_report_quality(normalized, technical_html, technical_split_dir)
        assert not failures, failures

    print("generate-report smoke tests passed")


if __name__ == "__main__":
    main()
