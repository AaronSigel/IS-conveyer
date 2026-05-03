#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${PROJECT_ROOT}/artifacts"
RUNS_DIR="${ARTIFACTS_DIR}/runs"

HOSTS="target1,target2"
OUTPUT_PREFIX=""
OUTPUT_DIR=""
LEGACY_PREFIX_PATHS=0
RUN_ID=""
METADATA_PATH=""

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
  RUN_ID="$(basename "${OUTPUT_DIR}")"
  UNIFIED_PATH="${OUTPUT_DIR}/unified-findings.json"
  RAW_ALERTS_PATH="${OUTPUT_DIR}/raw/wazuh-sca.json"
  RAW_VULNS_PATH="${OUTPUT_DIR}/raw/wazuh-vulnerabilities.json"
  REPORT_PATH="${OUTPUT_DIR}/draft-report.md"
  NORMALIZED_REPORT_PATH="${OUTPUT_DIR}/normalized_report.json"
  TECHNICAL_HTML_PATH="${OUTPUT_DIR}/technical_report.html"
  TECHNICAL_PDF_PATH="${OUTPUT_DIR}/technical_report.pdf"
  SPLIT_REPORTS_DIR="${OUTPUT_DIR}/reports"
  METADATA_PATH="${OUTPUT_DIR}/metadata.json"
elif [[ -n "${OUTPUT_PREFIX}" ]]; then
  NORMALIZED_PREFIX="${OUTPUT_PREFIX#-}"
  NORMALIZED_PREFIX="${NORMALIZED_PREFIX%-}"
  if [[ -z "${NORMALIZED_PREFIX}" ]]; then
    echo "Output prefix must not be empty" >&2
    exit 2
  fi
  RUN_ID="${NORMALIZED_PREFIX}-$(date -u '+%Y%m%dT%H%M%SZ')"
  OUTPUT_DIR="${RUNS_DIR}/${RUN_ID}"
  mkdir -p "${OUTPUT_DIR}/raw"
  UNIFIED_PATH="${OUTPUT_DIR}/unified-findings.json"
  RAW_ALERTS_PATH="${OUTPUT_DIR}/raw/wazuh-sca.json"
  RAW_VULNS_PATH="${OUTPUT_DIR}/raw/wazuh-vulnerabilities.json"
  REPORT_PATH="${OUTPUT_DIR}/draft-report.md"
  NORMALIZED_REPORT_PATH="${OUTPUT_DIR}/normalized_report.json"
  TECHNICAL_HTML_PATH="${OUTPUT_DIR}/technical_report.html"
  TECHNICAL_PDF_PATH="${OUTPUT_DIR}/technical_report.pdf"
  SPLIT_REPORTS_DIR="${OUTPUT_DIR}/reports"
  METADATA_PATH="${OUTPUT_DIR}/metadata.json"
  LEGACY_PREFIX_PATHS=1
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

if [[ -n "${METADATA_PATH}" ]]; then
  HOSTS_JSON="$(HOSTS="${HOSTS}" python3 - <<'PY'
import json
import os
print(json.dumps([item.strip() for item in os.environ["HOSTS"].split(",") if item.strip()], ensure_ascii=False))
PY
)"
  RUN_ID="${RUN_ID}" HOSTS_JSON="${HOSTS_JSON}" METADATA_PATH="${METADATA_PATH}" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["METADATA_PATH"])
metadata = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
run_id = os.environ["RUN_ID"]
hosts = json.loads(os.environ["HOSTS_JSON"])
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
metadata.update(
    {
        "id": run_id,
        "run_id": run_id,
        "status": "running",
        "mode": "scan_and_report",
        "hosts": hosts,
        "profile_id": "cis_ubuntu24-04",
        "started_at": metadata.get("started_at") or now,
        "artifacts": {
            "metadata": "metadata.json",
            "findings": "unified-findings.json",
            "normalized_report": "normalized_report.json",
            "html": "technical_report.html",
            "pdf": "technical_report.pdf",
            "raw_sca": "raw/wazuh-sca.json",
            "raw_vulnerabilities": "raw/wazuh-vulnerabilities.json",
            "legacy_markdown": "draft-report.md",
        },
    }
)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
fi

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
  --metadata "${METADATA_PATH:-config/report-metadata.yml}"
  --output "${REPORT_PATH}"
  --normalized-output "${NORMALIZED_REPORT_PATH}"
  --html-output "${TECHNICAL_HTML_PATH}"
  --pdf-output "${TECHNICAL_PDF_PATH}"
)
if [[ -n "${SPLIT_REPORTS_DIR}" ]]; then
  generate_args+=(--split-output-dir "${SPLIT_REPORTS_DIR}")
fi

python3 -m is_conveyer report -- "${generate_args[@]}"

if [[ -n "${METADATA_PATH}" ]]; then
  METADATA_PATH="${METADATA_PATH}" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["METADATA_PATH"])
metadata = json.loads(path.read_text(encoding="utf-8"))
metadata["status"] = "succeeded"
metadata["finished_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
fi

if [[ "${LEGACY_PREFIX_PATHS}" -eq 1 ]]; then
  cp "${UNIFIED_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-unified-findings.json"
  cp "${RAW_ALERTS_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-raw-wazuh-alerts.json"
  cp "${RAW_VULNS_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-raw-wazuh-vulnerabilities.json"
  cp "${REPORT_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-draft-report.md"
  cp "${NORMALIZED_REPORT_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-normalized_report.json"
  cp "${TECHNICAL_HTML_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-technical_report.html"
  if [[ -f "${TECHNICAL_PDF_PATH}" ]]; then
    cp "${TECHNICAL_PDF_PATH}" "${ARTIFACTS_DIR}/${NORMALIZED_PREFIX}-technical_report.pdf"
  fi
fi

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
if [[ -n "${OUTPUT_DIR}" ]]; then
  echo "run directory: ${OUTPUT_DIR}"
fi
