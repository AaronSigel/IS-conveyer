#!/usr/bin/env bash
# Ansible SSH to Vagrant NAT forwards: choose the host address that reaches Windows from this environment.
# Modern WSL2 (incl. mirrored networking): 127.0.0.1 reaches Windows listeners. Older WSL2: use resolv.conf nameserver.

if [[ -f /proc/version ]] && grep -qi microsoft /proc/version; then
  if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 2222 2>/dev/null; then
    export WINDOWS_HOST_IP=127.0.0.1
  else
    set +o pipefail
    _WINDOWS_IP="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf 2>/dev/null)"
    if [[ -z "${_WINDOWS_IP}" ]]; then
      _WINDOWS_IP="$(ip route show default 2>/dev/null | awk '$1=="default" && $2=="via" {print $3; exit}')"
    fi
    set -o pipefail
    export WINDOWS_HOST_IP="${_WINDOWS_IP:-127.0.0.1}"
  fi
else
  export WINDOWS_HOST_IP="${WINDOWS_HOST_IP:-127.0.0.1}"
fi
