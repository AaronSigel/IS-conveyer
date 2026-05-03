#!/usr/bin/env python3
import pathlib
import sys
import tempfile


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from web import reports, runs


SAMPLE_FINDINGS = PROJECT_ROOT / "report" / "samples" / "sample-findings.json"


def test_split_export_creates_two_reports_per_host():
    with tempfile.TemporaryDirectory() as tmp:
        original_runs_dir = runs.RUNS_DIR
        runs.RUNS_DIR = pathlib.Path(tmp) / "runs"
        run_id = "run-test"
        run_dir = runs.run_dir(run_id)
        run_dir.mkdir(parents=True)
        (run_dir / "exports").mkdir()
        runs.write_json(run_dir / "exports" / "exports.json", {"exports": []})
        runs.write_json(
            run_dir / "metadata.json",
            {"id": run_id, "status": "succeeded", "hosts": ["target1", "target2"], "profile_id": "cis_ubuntu24-04"},
        )
        (run_dir / "unified-findings.json").write_text(SAMPLE_FINDINGS.read_text(encoding="utf-8"), encoding="utf-8")

        original_render_pdf = reports.render_pdf
        reports.render_pdf = lambda html_path, pdf_path: pathlib.Path(pdf_path).write_bytes(b"%PDF-1.4\n")
        try:
            export = reports.create_export(
                run_id,
                "Vulnerability reports",
                {
                    "finding_type": {"op": "eq", "value": "software_vulnerability"},
                    "status": {"op": "in", "value": ["fail"]},
                },
                export_id="default",
                report_mode="split",
            )
        finally:
            reports.render_pdf = original_render_pdf
            runs.RUNS_DIR = original_runs_dir

        assert set(export["reports"]) == {
            "target1-configuration",
            "target1-packages",
            "target2-configuration",
            "target2-packages",
        }
        export_dir = run_dir / "exports" / "default"
        for report in export["reports"].values():
            files = report["files"]
            assert (export_dir / files["json"]).exists()
            assert (export_dir / files["html"]).exists()
            assert (export_dir / files["pdf"]).exists()


def main():
    test_split_export_creates_two_reports_per_host()
    print("web report split tests passed")


if __name__ == "__main__":
    main()
