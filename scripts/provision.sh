#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVENTORY="${PROJECT_ROOT}/ansible/inventory/hosts.ini"
ANSIBLE_CONFIG_PATH="${PROJECT_ROOT}/ansible.cfg"
ANSIBLE_ROLES_PATH="${PROJECT_ROOT}/ansible/roles"
RUNTIME_INVENTORY="$(mktemp)"
VAGRANT_KEY="${VAGRANT_INSECURE_PRIVATE_KEY:-$HOME/.vagrant.d/insecure_private_key}"

cd "${PROJECT_ROOT}"
# shellcheck source=scripts/env-windows-host-ip.sh
. "${SCRIPT_DIR}/env-windows-host-ip.sh"
trap 'rm -f "${RUNTIME_INVENTORY}"' EXIT

export ANSIBLE_CONFIG="${ANSIBLE_CONFIG_PATH}"
export ANSIBLE_ROLES_PATH
sed "s/ansible_host=127.0.0.1/ansible_host=${WINDOWS_HOST_IP}/g" "${INVENTORY}" > "${RUNTIME_INVENTORY}"
cat >> "${RUNTIME_INVENTORY}" <<EOF
ansible_ssh_private_key_file=${VAGRANT_KEY}
EOF

ansible-playbook -i "${RUNTIME_INVENTORY}" ansible/playbooks/bootstrap.yml "$@"
ansible-playbook -i "${RUNTIME_INVENTORY}" ansible/playbooks/targets.yml "$@"
ansible-playbook -i "${RUNTIME_INVENTORY}" ansible/playbooks/wazuh.yml "$@"
