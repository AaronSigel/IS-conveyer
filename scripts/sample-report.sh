#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"
python3 -m is_conveyer report -- \
  --findings report/samples/sample-findings.json \
  --profile profiles/cis_ubuntu24-04.yml \
  --metadata config/report-metadata.yml \
  --output artifacts/sample-draft-report.md
