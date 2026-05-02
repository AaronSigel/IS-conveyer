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
  # Match only the running state line for this VM (avoid matching "not running" or another VM's line).
  if vagrant status "${vm}" 2>/dev/null | grep -qE "^${vm}[[:space:]]+running[[:space:]]+\\("; then
    vagrant ssh "${vm}" -c "${cmd}"
  else
    echo "${vm}: vagrant reports VM is not running (or status could not be read)"
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
  # Config lives under /var/ossec/etc (often mode 750): use sudo so vagrant can stat the file.
  run_vm "${vm}" "sudo test -f /var/ossec/etc/ossec.conf && echo agent_config_present || echo agent_config_missing; systemctl is-active wazuh-agent 2>/dev/null || true"
done
