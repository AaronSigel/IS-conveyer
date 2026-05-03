import json
import re
import shutil
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
RUNS_DIR = ARTIFACTS_DIR / "runs"
LATEST_PATH = ARTIFACTS_DIR / "latest.json"
PROFILE_ID = "cis_ubuntu24-04"
PROFILE_PATH = PROJECT_ROOT / "profiles" / f"{PROFILE_ID}.yml"
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def make_run_id() -> str:
    return f"{datetime.now().astimezone():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:8]}"


def run_dir(run_id: str) -> Path:
    validate_component(run_id, "run id")
    return RUNS_DIR / run_id


def validate_component(value: str, label: str = "path component") -> None:
    if not SAFE_COMPONENT.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Invalid {label}")


def empty_summary() -> dict[str, int]:
    return {"total": 0, "pass": 0, "fail": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


def _normalize_run_metadata(record: Any) -> dict[str, Any] | None:
    """Return a dict safe for dashboard templates, or None if the row should be skipped."""
    if not isinstance(record, dict):
        return None
    run_id = record.get("id")
    if not run_id or not isinstance(run_id, str):
        return None
    summary = empty_summary()
    raw_summary = record.get("summary")
    if isinstance(raw_summary, dict):
        for key in summary:
            try:
                summary[key] = int(raw_summary.get(key, 0))
            except (TypeError, ValueError):
                summary[key] = 0
    hosts = record.get("hosts")
    if not isinstance(hosts, list):
        hosts = []
    else:
        hosts = [str(h) for h in hosts if h is not None]
    status = record.get("status")
    out = dict(record)
    out["id"] = run_id
    out["summary"] = summary
    out["hosts"] = hosts
    out["status"] = str(status) if status is not None else "unknown"
    return out


def create_run(hosts: list[str], create_default_export: bool = True) -> dict[str, Any]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = make_run_id()
    path = run_dir(run_id)
    if path.exists():
        raise FileExistsError(f"Run directory already exists: {path}")
    path.mkdir(parents=True)
    (path / "raw").mkdir()
    (path / "profile").mkdir()
    (path / "exports").mkdir()
    write_json(path / "exports" / "exports.json", {"exports": []})
    request = {
        "hosts": hosts,
        "profile": PROFILE_ID,
        "created_from_ui": True,
        "create_default_export": create_default_export,
        "default_export_filters": {"status": {"op": "in", "value": ["fail"]}},
    }
    metadata = {
        "id": run_id,
        "status": "created",
        "mode": "scan_and_report",
        "hosts": hosts,
        "profile_id": PROFILE_ID,
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "returncode": None,
        "summary": empty_summary(),
        "artifacts": {"findings": "unified-findings.json", "log": "logs.txt", "summary": "summary.json"},
    }
    write_json(path / "request.json", request)
    write_json(path / "metadata.json", metadata)
    (path / "logs.txt").touch()
    if PROFILE_PATH.exists():
        shutil.copy2(PROFILE_PATH, path / "profile" / PROFILE_PATH.name)
    write_json(LATEST_PATH, {"latest_run_id": run_id})
    return metadata


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    counts["total"] = len(findings)
    for item in findings:
        counts[str(item.get("status", "")).lower()] += 1
        counts[str(item.get("severity", "")).lower()] += 1
    summary = empty_summary()
    for key in summary:
        summary[key] = int(counts.get(key, 0))
    return summary


def load_metadata(run_id: str) -> dict[str, Any]:
    return read_json(run_dir(run_id) / "metadata.json", {})


def save_metadata(metadata: dict[str, Any]) -> None:
    write_json(run_dir(metadata["id"]) / "metadata.json", metadata)


def update_metadata(run_id: str, **updates: Any) -> dict[str, Any]:
    metadata = load_metadata(run_id)
    metadata.update(updates)
    save_metadata(metadata)
    return metadata


def finish_run(run_id: str, returncode: int) -> dict[str, Any]:
    path = run_dir(run_id)
    metadata = load_metadata(run_id)
    finished_at = now_iso()
    started_at = metadata.get("started_at")
    duration = None
    if started_at:
        duration = int((datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds())
    findings = read_json(path / "unified-findings.json", [])
    summary = summarize_findings(findings if isinstance(findings, list) else [])
    write_json(path / "summary.json", summary)
    metadata.update(
        {
            "status": "succeeded" if returncode == 0 else "failed",
            "finished_at": finished_at,
            "duration_seconds": duration,
            "returncode": returncode,
            "summary": summary,
        }
    )
    save_metadata(metadata)
    write_json(LATEST_PATH, {"latest_run_id": run_id})
    return metadata


def list_runs() -> list[dict[str, Any]]:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for metadata_path in RUNS_DIR.glob("*/metadata.json"):
        try:
            raw = metadata_path.read_text(encoding="utf-8")
            metadata = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue
        normalized = _normalize_run_metadata(metadata)
        if normalized:
            items.append(normalized)
    return sorted(items, key=lambda item: item.get("started_at") or item.get("id", ""), reverse=True)


def load_findings(run_id: str) -> list[dict[str, Any]]:
    data = read_json(run_dir(run_id) / "unified-findings.json", [])
    return data if isinstance(data, list) else []


def list_exports(run_id: str) -> list[dict[str, Any]]:
    data = read_json(run_dir(run_id) / "exports" / "exports.json", {"exports": []})
    return data.get("exports", []) if isinstance(data, dict) else []


def save_exports_index(run_id: str, exports: list[dict[str, Any]]) -> None:
    write_json(run_dir(run_id) / "exports" / "exports.json", {"exports": exports})
