from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from typing import Sequence

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _run(cmd: Sequence[str]) -> int:
    return subprocess.run(cmd, cwd=PROJECT_ROOT).returncode


def _passthrough_args(values: Sequence[str]) -> list[str]:
    args = list(values)
    if args and args[0] == "--":
        return args[1:]
    return args


def cmd_report(args: argparse.Namespace) -> int:
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "generate-report.py"), *_passthrough_args(args.script_args)]
    return _run(cmd)


def cmd_export(args: argparse.Namespace) -> int:
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "export-findings.py"), *_passthrough_args(args.script_args)]
    return _run(cmd)


def cmd_scan_and_report(args: argparse.Namespace) -> int:
    script = PROJECT_ROOT / "scripts" / "scan-and-report.sh"
    cmd = ["bash", str(script), *_passthrough_args(args.script_args)]
    return _run(cmd)


def cmd_run_ui(args: argparse.Namespace) -> int:
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "web.app:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.reload:
        cmd.append("--reload")
    return _run(cmd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m is_conveyer", description="Unified IS-conveyer CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="Generate report artifacts")
    report.add_argument("script_args", nargs=argparse.REMAINDER, help="Arguments passed to scripts/generate-report.py")
    report.set_defaults(func=cmd_report)

    export = subparsers.add_parser("export", help="Export unified findings from Wazuh")
    export.add_argument("script_args", nargs=argparse.REMAINDER, help="Arguments passed to scripts/export-findings.py")
    export.set_defaults(func=cmd_export)

    scan = subparsers.add_parser("scan-and-report", help="Run full scan and report pipeline")
    scan.add_argument("script_args", nargs=argparse.REMAINDER, help="Arguments passed to scripts/scan-and-report.sh")
    scan.set_defaults(func=cmd_scan_and_report)

    ui = subparsers.add_parser("run-ui", help="Run Web UI")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8080)
    ui.add_argument("--reload", action="store_true", default=True)
    ui.set_defaults(func=cmd_run_ui)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
