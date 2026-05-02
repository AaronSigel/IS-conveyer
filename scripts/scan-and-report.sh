#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "[scan-and-report] failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOSTS="target1,target2"
OUTPUT_PREFIX=""
OUTPUT_DIR=""
EXTRA_SCAN_ARGS=()

stage() {
  printf '[scan-and-report] %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1"
}

usage() {
  cat <<'EOF'
Usage: ./scripts/scan-and-report.sh [--hosts target1,target2] [--output-prefix prefix] [--output-dir dir] [scan args]

Runs the scan pipeline only:
  1. trigger host scan
  2. wait for fresh Wazuh data
  3. export findings
  4. generate report
EOF
}

while (($# > 0)); do
  case "$1" in
    --hosts)
      HOSTS="$2"
      EXTRA_SCAN_ARGS+=("$1" "$2")
      shift 2
      ;;
    --output-prefix)
      OUTPUT_PREFIX="$2"
      EXTRA_SCAN_ARGS+=("$1" "$2")
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      EXTRA_SCAN_ARGS+=("$1")
      shift
      ;;
  esac
done

cd "${PROJECT_ROOT}"
# shellcheck source=scripts/env-windows-host-ip.sh
. "${SCRIPT_DIR}/env-windows-host-ip.sh"

stage "starting host scan"
python3 scripts/run-host-scan.py "${EXTRA_SCAN_ARGS[@]}"
stage "host scan finished"

collect_args=(--hosts "${HOSTS}")
if [[ -n "${OUTPUT_PREFIX}" ]]; then
  collect_args+=(--output-prefix "${OUTPUT_PREFIX}")
fi
if [[ -n "${OUTPUT_DIR}" ]]; then
  collect_args+=(--output-dir "${OUTPUT_DIR}")
fi

stage "starting report collection"
bash ./scripts/collect-report.sh "${collect_args[@]}"
stage "report collection finished"
