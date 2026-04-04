#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVENTORY="${PROJECT_ROOT}/ansible/inventory/hosts.ini"

cd "${PROJECT_ROOT}"

ansible-playbook -i "${INVENTORY}" ansible/playbooks/bootstrap.yml "$@"
ansible-playbook -i "${INVENTORY}" ansible/playbooks/targets.yml "$@"
ansible-playbook -i "${INVENTORY}" ansible/playbooks/wazuh.yml "$@"
