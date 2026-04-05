#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INTERVAL="${1:-10}"

cd "${PROJECT_ROOT}"

while true; do
  clear
  printf 'timestamp: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  "${SCRIPT_DIR}/capture-state.sh" || true
  sleep "${INTERVAL}"
done
