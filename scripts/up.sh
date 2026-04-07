#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

if (($# > 0)); then
  vagrant up "$@"
else
  for machine in wazuh target1 target2; do
    vagrant up "${machine}"
  done
fi
