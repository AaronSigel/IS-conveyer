import subprocess
import threading

from web import runs
from web.reports import create_export


ALLOWED_COMMANDS = {"scan_and_report": ["./scripts/scan-and-report.sh"]}
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
    command = ALLOWED_COMMANDS["scan_and_report"] + ["--hosts", ",".join(hosts), "--output-dir", str(path)]
    returncode = 1
    try:
        with (path / "logs.txt").open("a", encoding="utf-8") as log:
            log.write(f"$ {' '.join(command)}\n")
            log.flush()
            process = subprocess.Popen(
                command,
                cwd=runs.PROJECT_ROOT,
                shell=False,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            returncode = process.wait()
        metadata = runs.finish_run(run_id, returncode)
        if metadata["status"] == "succeeded" and create_default_export:
            create_export(run_id, "Default failed findings", {"status": {"op": "in", "value": ["fail"]}}, export_id="default")
    except Exception as exc:
        with (path / "logs.txt").open("a", encoding="utf-8") as log:
            log.write(f"\nUI job failed: {exc}\n")
        runs.finish_run(run_id, returncode)
    finally:
        _active_run_id = None
        _scan_lock.release()
