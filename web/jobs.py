import shutil
import subprocess
import sys
import threading
from pathlib import Path

from web import runs
from web.reports import create_export


ALLOWED_COMMANDS = {"scan_and_report": ["./scripts/scan-and-report.sh"]}


def _scan_and_report_argv(extra: list[str]) -> list[str]:
    """Build argv for scan-and-report.

    On Windows, Git-bash or Store `bash.exe` stubs often raise WinError 193; use the same
    PowerShell+WSL entrypoint as scripts/windows/scan-and-report.ps1.
    """
    if sys.platform == "win32":
        ps1 = runs.PROJECT_ROOT / "scripts" / "windows" / "scan-and-report.ps1"
        if not ps1.is_file():
            raise RuntimeError(f"Не найден {ps1}")
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            raise RuntimeError("Не найден powershell.exe в PATH.")
        return [
            powershell,
            "-ExecutionPolicy",
            "Bypass",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ps1.resolve()),
            *extra,
        ]
    return [*ALLOWED_COMMANDS["scan_and_report"], *extra]


def _run_output_dir_for_scan_cli(path: Path) -> str:
    """Bash under WSL expects a repo-relative or POSIX path, not ``E:\\...``."""
    root = runs.PROJECT_ROOT.resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.as_posix()
_scan_lock = threading.Lock()
_active_run_id: str | None = None


def active_run_id() -> str | None:
    return _active_run_id


def start_scan(hosts: list[str], create_default_export: bool = True) -> tuple[bool, str]:
    global _active_run_id
    if not _scan_lock.acquire(blocking=False):
        return False, "Проверка уже выполняется. Дождитесь завершения текущего запуска."
    metadata = runs.create_run(hosts, create_default_export=create_default_export)
    _active_run_id = metadata["id"]
    thread = threading.Thread(target=_run_scan, args=(metadata["id"], hosts, create_default_export), daemon=True)
    thread.start()
    return True, metadata["id"]


def _run_scan(run_id: str, hosts: list[str], create_default_export: bool) -> None:
    global _active_run_id
    path = runs.run_dir(run_id)
    runs.update_metadata(run_id, status="running", started_at=runs.now_iso())
    command = _scan_and_report_argv(
        ["--hosts", ",".join(hosts), "--output-dir", _run_output_dir_for_scan_cli(path)]
    )
    returncode = 1
    try:
        with (path / "logs.txt").open("a", encoding="utf-8") as log:
            log.write(f"$ {' '.join(command)}\n")
            log.flush()
            process = subprocess.Popen(
                command,
                cwd=runs.PROJECT_ROOT,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            log.write("[ui-job] process started; waiting for completion\n")
            log.flush()
            returncode = process.wait()
        metadata = runs.finish_run(run_id, returncode)
        if metadata["status"] == "succeeded" and create_default_export:
            create_export(
                run_id,
                "Default vulnerability reports",
                {
                    "finding_type": {"op": "eq", "value": "software_vulnerability"},
                    "status": {"op": "in", "value": ["fail"]},
                },
                export_id="default",
                report_mode="split",
            )
    except Exception as exc:
        with (path / "logs.txt").open("a", encoding="utf-8") as log:
            log.write(f"\nUI job failed: {exc}\n")
        runs.finish_run(run_id, returncode)
    finally:
        _active_run_id = None
        _scan_lock.release()
