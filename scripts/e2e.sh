#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_SMOKE_TEST=1
SCAN_ARGS=()

usage() {
  cat <<'EOF'
Usage: ./scripts/e2e.sh [--skip-smoke-test] [run-host-scan args]

Runs the full local pipeline:
  1. vagrant up
  2. ansible provisioning
  3. smoke test
  4. Wazuh scan + findings export + markdown report

Examples:
  ./scripts/e2e.sh
  ./scripts/e2e.sh --hosts target1 --output-prefix target1-manual
  ./scripts/e2e.sh --skip-smoke-test --timeout 900
EOF
}

while (($# > 0)); do
  case "$1" in
    --skip-smoke-test)
      RUN_SMOKE_TEST=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      SCAN_ARGS+=("$1")
      shift
      ;;
  esac
done

cd "${PROJECT_ROOT}"

echo "[1/4] Starting virtual machines"
./scripts/up.sh

echo "[2/4] Provisioning hosts and Wazuh components"
./scripts/provision.sh

if (( RUN_SMOKE_TEST )); then
  echo "[3/4] Running smoke test"
  ./scripts/smoke-test.sh
else
  echo "[3/4] Smoke test skipped"
fi

echo "[4/4] Running scan and generating report"
./scripts/scan-and-report.sh "${SCAN_ARGS[@]}"
