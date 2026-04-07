#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVENTORY="${PROJECT_ROOT}/ansible/inventory/hosts.ini"
ANSIBLE_CONFIG_PATH="${PROJECT_ROOT}/ansible.cfg"
ANSIBLE_ROLES_PATH="${PROJECT_ROOT}/ansible/roles"
WINDOWS_HOST_IP="${WINDOWS_HOST_IP:-127.0.0.1}"
RUNTIME_INVENTORY="$(mktemp)"
VAGRANT_KEY="${VAGRANT_INSECURE_PRIVATE_KEY:-$HOME/.vagrant.d/insecure_private_key}"

cd "${PROJECT_ROOT}"
trap 'rm -f "${RUNTIME_INVENTORY}"' EXIT

export ANSIBLE_CONFIG="${ANSIBLE_CONFIG_PATH}"
export ANSIBLE_ROLES_PATH
sed "s/ansible_host=127.0.0.1/ansible_host=${WINDOWS_HOST_IP}/g" "${INVENTORY}" > "${RUNTIME_INVENTORY}"
cat >> "${RUNTIME_INVENTORY}" <<EOF
ansible_ssh_private_key_file=${VAGRANT_INSECURE_PRIVATE_KEY}
EOF

read_inventory_value() {
  local machine="$1"
  local key="$2"

  awk -v host="$machine" -v lookup_key="$key" '
    $1 ~ /^\[/ {
      in_targets = 0
    }
    $1 == host {
      for (i = 1; i <= NF; i++) {
        split($i, pair, "=")
        if (pair[1] == lookup_key) {
          print pair[2]
          exit
        }
      }
    }
  ' "${RUNTIME_INVENTORY}"
}

ssh_vm() {
  local machine="$1"
  local command="$2"
  local port
  port="$(read_inventory_value "$machine" "ansible_port")"

  ssh -F /dev/null \
    -o UserKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=no \
    -i "${VAGRANT_KEY}" \
    -p "${port}" \
    "vagrant@${WINDOWS_HOST_IP}" \
    "${command}"
}

ssh_vm wazuh_manager "echo wazuh-ok"
ssh_vm target1 "echo target1-ok"
ssh_vm target2 "echo target2-ok"
ansible all -i "${RUNTIME_INVENTORY}" -m ping

INDEXER_PASS_FILE="${PROJECT_ROOT}/artifacts/wazuh-indexer-password.txt"
if [[ -f "${INDEXER_PASS_FILE}" ]]; then
  INDEXER_PASS="$(tr -d '\n' < "${INDEXER_PASS_FILE}")"
  SSH_HOST="${WINDOWS_HOST_IP}"
  SSH_PORT="$(read_inventory_value wazuh_manager ansible_port)"
  SSH_USER="vagrant"
  SSH_KEY="${VAGRANT_KEY}"

  for attempt in $(seq 1 20); do
    count="$(
      ssh -F /dev/null \
        -o UserKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=no \
        -i "${SSH_KEY}" \
        -p "${SSH_PORT}" \
        "${SSH_USER}@${SSH_HOST}" \
        "sudo curl -sk -u admin:${INDEXER_PASS} https://127.0.0.1:9200/wazuh-states-vulnerabilities*/_count" \
        2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count", 0))'
    )"

    if [[ "${count}" =~ ^[0-9]+$ ]] && (( count > 0 )); then
      break
    fi

    if (( attempt == 20 )); then
      echo "wazuh-vulnerabilities-empty"
      exit 1
    fi

    sleep 15
  done
fi
