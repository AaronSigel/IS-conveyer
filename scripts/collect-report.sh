#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${PROJECT_ROOT}/artifacts"

HOSTS="target1,target2"
OUTPUT_PREFIX=""

usage() {
  cat <<'EOF'
Usage: ./scripts/collect-report.sh [--hosts target1,target2] [--output-prefix prefix]

Exports normalized findings and builds a markdown report from ready scan data.
EOF
}

while (($# > 0)); do
  case "$1" in
    --hosts)
      HOSTS="$2"
      shift 2
      ;;
    --output-prefix)
      OUTPUT_PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "${OUTPUT_PREFIX}" ]]; then
  NORMALIZED_PREFIX="${OUTPUT_PREFIX#-}"
  NORMALIZED_PREFIX="${NORMALIZED_PREFIX%-}"
  if [[ -z "${NORMALIZED_PREFIX}" ]]; then
    echo "Output prefix must not be empty" >&2
    exit 2
  fi
  UNIFIED_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-unified-findings.json"
  RAW_ALERTS_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-raw-wazuh-alerts.json"
  RAW_VULNS_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-raw-wazuh-vulnerabilities.json"
  REPORT_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-draft-report.md"
else
  UNIFIED_PATH="${ARTIFACTS_DIR}/unified-findings.json"
  RAW_ALERTS_PATH="${ARTIFACTS_DIR}/raw-wazuh-alerts.json"
  RAW_VULNS_PATH="${ARTIFACTS_DIR}/raw-wazuh-vulnerabilities.json"
  REPORT_PATH="${ARTIFACTS_DIR}/draft-report.md"
fi

cd "${PROJECT_ROOT}"

python3 scripts/export-findings.py \
  --hosts "${HOSTS}" \
  --output "${UNIFIED_PATH}" \
  --raw-alerts-output "${RAW_ALERTS_PATH}" \
  --raw-vulns-output "${RAW_VULNS_PATH}"

python3 scripts/generate-report.py \
  --input "${UNIFIED_PATH}" \
  --output "${REPORT_PATH}"

echo "unified findings: ${UNIFIED_PATH}"
echo "raw alerts: ${RAW_ALERTS_PATH}"
echo "raw vulnerabilities: ${RAW_VULNS_PATH}"
echo "report: ${REPORT_PATH}"
