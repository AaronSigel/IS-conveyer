#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOSTS="target1,target2"
OUTPUT_PREFIX=""
EXTRA_SCAN_ARGS=()

usage() {
  cat <<'EOF'
Usage: ./scripts/scan-and-report.sh [--hosts target1,target2] [--output-prefix prefix] [scan args]

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

./scripts/run-host-scan.py "${EXTRA_SCAN_ARGS[@]}"
bash ./scripts/collect-report.sh --hosts "${HOSTS}" ${OUTPUT_PREFIX:+--output-prefix "${OUTPUT_PREFIX}"}
