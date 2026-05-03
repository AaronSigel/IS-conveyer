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

    print("generate-report smoke tests passed")


if __name__ == "__main__":
    main()
