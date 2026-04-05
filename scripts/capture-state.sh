#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

section() {
  printf '\n== %s ==\n' "$1"
}

run_vm() {
  local vm="$1"
  local cmd="$2"
  if vagrant status "${vm}" 2>/dev/null | grep -q "running"; then
    vagrant ssh "${vm}" -c "${cmd}"
  else
    echo "${vm}: not running"
  fi
}

section "Vagrant Status"
vagrant status || true

section "Manager Filesystems"
run_vm wazuh "df -h / /var /tmp /var/ossec/queue 2>/dev/null || true"

section "Manager Disk Usage"
run_vm wazuh "sudo du -xhd1 /var /var/ossec 2>/dev/null | sort -h"

section "Manager Services"
run_vm wazuh "sudo systemctl is-active wazuh-manager wazuh-indexer filebeat wazuh-dashboard 2>/dev/null || true"

section "Manager Install Log"
run_vm wazuh "sudo tail -n 60 /var/log/wazuh-install.log 2>/dev/null || echo /var/log/wazuh-install.log missing"

section "Manager Wazuh Log"
run_vm wazuh "sudo tail -n 60 /var/ossec/logs/ossec.log 2>/dev/null || echo /var/ossec/logs/ossec.log missing"

section "Agent Status"
for vm in target1 target2; do
  echo "-- ${vm} --"
  run_vm "${vm}" "test -f /var/ossec/etc/ossec.conf && echo agent_present || echo agent_missing; systemctl is-active wazuh-agent 2>/dev/null || true"
done
