#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVENTORY="${PROJECT_ROOT}/ansible/inventory/hosts.ini"

cd "${PROJECT_ROOT}"

vagrant status
vagrant ssh wazuh -c "echo wazuh-ok"
vagrant ssh target1 -c "echo target1-ok"
vagrant ssh target2 -c "echo target2-ok"
ansible all -i "${INVENTORY}" -m ping
