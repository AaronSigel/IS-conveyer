#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATOR = PROJECT_ROOT / "scripts" / "generate-report.py"
SAMPLE_FINDINGS = PROJECT_ROOT / "report" / "samples" / "sample-findings.json"
PROFILE = PROJECT_ROOT / "profiles" / "host-baseline-v1.yml"
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


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)

        full_report = run_report(tmpdir / "full.md")
        assert_sections(full_report)
        assert_no_forbidden_sections(full_report)
        assert full_report.count("### 5.") == 4, "Expected one passport per sample finding"

        high_report = run_report(tmpdir / "high.md", "--severity", "high")
        assert "Запрет входа root по SSH" in high_report
        assert "Запрет X11 forwarding" not in high_report
        assert "Sudo chroot option" not in high_report
        assert high_report.count("### 5.") == 1

        failed_report = run_report(tmpdir / "failed.md", "--status", "failed")
        assert "auditd установлен" not in failed_report
        assert failed_report.count("### 5.") == 3

        cvss_report = run_report(tmpdir / "cvss.md", "--source", "wazuh_vulnerability", "--cvss-min", "5.0")
        assert "Sudo chroot option" in cvss_report
        assert "Запрет входа root по SSH" not in cvss_report
        assert cvss_report.count("### 5.") == 1

        empty_report = run_report(tmpdir / "empty.md", "--severity", "low", "--status", "failed")
        assert "По заданным критериям фильтрации уязвимости и несоответствия не выявлены." in empty_report
        assert "### 5." not in empty_report

    print("generate-report smoke tests passed")


if __name__ == "__main__":
    main()
