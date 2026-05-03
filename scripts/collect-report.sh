#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${PROJECT_ROOT}/artifacts"

HOSTS="target1,target2"
OUTPUT_PREFIX=""
OUTPUT_DIR=""

usage() {
  cat <<'EOF'
Usage: ./scripts/collect-report.sh [--hosts target1,target2] [--output-prefix prefix] [--output-dir dir]

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
    --output-dir)
      OUTPUT_DIR="$2"
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

if [[ -n "${OUTPUT_DIR}" ]]; then
  mkdir -p "${OUTPUT_DIR}/raw"
  UNIFIED_PATH="${OUTPUT_DIR}/unified-findings.json"
  RAW_ALERTS_PATH="${OUTPUT_DIR}/raw/wazuh-sca.json"
  RAW_VULNS_PATH="${OUTPUT_DIR}/raw/wazuh-vulnerabilities.json"
  REPORT_PATH="${OUTPUT_DIR}/draft-report.md"
  NORMALIZED_REPORT_PATH="${OUTPUT_DIR}/normalized_report.json"
  TECHNICAL_HTML_PATH="${OUTPUT_DIR}/technical_report.html"
  TECHNICAL_PDF_PATH="${OUTPUT_DIR}/technical_report.pdf"
  SPLIT_REPORTS_DIR="${OUTPUT_DIR}/reports"
elif [[ -n "${OUTPUT_PREFIX}" ]]; then
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
  NORMALIZED_REPORT_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-normalized_report.json"
  TECHNICAL_HTML_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-technical_report.html"
  TECHNICAL_PDF_PATH="${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-technical_report.pdf"
  SPLIT_REPORTS_DIR=""
else
  UNIFIED_PATH="${ARTIFACTS_DIR}/unified-findings.json"
  RAW_ALERTS_PATH="${ARTIFACTS_DIR}/raw-wazuh-alerts.json"
  RAW_VULNS_PATH="${ARTIFACTS_DIR}/raw-wazuh-vulnerabilities.json"
  REPORT_PATH="${ARTIFACTS_DIR}/draft-report.md"
  NORMALIZED_REPORT_PATH="${ARTIFACTS_DIR}/normalized_report.json"
  TECHNICAL_HTML_PATH="${ARTIFACTS_DIR}/technical_report.html"
  TECHNICAL_PDF_PATH="${ARTIFACTS_DIR}/technical_report.pdf"
  SPLIT_REPORTS_DIR=""
fi

cd "${PROJECT_ROOT}"

python3 -m is_conveyer export -- \
  --hosts "${HOSTS}" \
  --output "${UNIFIED_PATH}" \
  --raw-alerts-output "${RAW_ALERTS_PATH}" \
  --raw-vulns-output "${RAW_VULNS_PATH}"

if [[ -n "${OUTPUT_DIR}" ]]; then
  cp "${RAW_ALERTS_PATH}" "${OUTPUT_DIR}/raw/syscollector-packages.json"
fi

generate_args=(
  --findings "${UNIFIED_PATH}"
  --profile profiles/cis_ubuntu24-04.yml
  --metadata config/report-metadata.yml
  --output "${REPORT_PATH}"
  --normalized-output "${NORMALIZED_REPORT_PATH}"
  --html-output "${TECHNICAL_HTML_PATH}"
  --pdf-output "${TECHNICAL_PDF_PATH}"
)
if [[ -n "${SPLIT_REPORTS_DIR}" ]]; then
  generate_args+=(--split-output-dir "${SPLIT_REPORTS_DIR}")
fi

python3 -m is_conveyer report -- "${generate_args[@]}"

echo "unified findings: ${UNIFIED_PATH}"
echo "raw alerts: ${RAW_ALERTS_PATH}"
echo "raw vulnerabilities: ${RAW_VULNS_PATH}"
echo "normalized report: ${NORMALIZED_REPORT_PATH}"
echo "technical html: ${TECHNICAL_HTML_PATH}"
echo "technical pdf: ${TECHNICAL_PDF_PATH}"
echo "legacy report path: ${REPORT_PATH}"
if [[ -n "${SPLIT_REPORTS_DIR}" ]]; then
  echo "split reports: ${SPLIT_REPORTS_DIR}"
fi
