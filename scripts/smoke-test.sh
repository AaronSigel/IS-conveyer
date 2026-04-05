#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVENTORY="${PROJECT_ROOT}/ansible/inventory/hosts.ini"

cd "${PROJECT_ROOT}"

read_vagrant_ssh_value() {
  local machine="$1"
  local key="$2"

  vagrant ssh-config "${machine}" | awk -v lookup_key="${key}" '
    $1 == lookup_key {
      $1 = ""
      sub(/^[[:space:]]+/, "", $0)
      gsub(/"/, "", $0)
      print $0
      exit
    }
  '
}

vagrant status
vagrant ssh wazuh -c "echo wazuh-ok"
vagrant ssh target1 -c "echo target1-ok"
vagrant ssh target2 -c "echo target2-ok"
ansible all -i "${INVENTORY}" -m ping

INDEXER_PASS_FILE="${PROJECT_ROOT}/artifacts/wazuh-indexer-password.txt"
if [[ -f "${INDEXER_PASS_FILE}" ]]; then
  INDEXER_PASS="$(tr -d '\n' < "${INDEXER_PASS_FILE}")"
  SSH_HOST="$(read_vagrant_ssh_value wazuh HostName)"
  SSH_PORT="$(read_vagrant_ssh_value wazuh Port)"
  SSH_USER="$(read_vagrant_ssh_value wazuh User)"
  SSH_KEY="$(read_vagrant_ssh_value wazuh IdentityFile)"

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
