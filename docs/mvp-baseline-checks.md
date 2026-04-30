# MVP Baseline Checks For Ubuntu 24.04

Документ фиксирует состав базовых проверок для MVP-демонстрации.

## Configuration Checks

Текущий набор configuration/SCA проверок пригоден для MVP: он даёт понятные pass/fail отличия между compliant и vulnerable hosts и покрывает типовые hardening-контроли.

| Area | Rule IDs |
| --- | --- |
| SSH hardening | `SSH_ROOT_LOGIN_DISABLED`, `SSH_PASSWORD_AUTH_DISABLED`, `SSH_EMPTY_PASSWORDS_DISABLED`, `SSH_X11_FORWARDING_DISABLED`, `SSH_MAX_AUTH_TRIES_LIMITED` |
| Firewall | `FIREWALL_UFW_ENABLED`, `FIREWALL_DEFAULT_DENY_INCOMING` |
| File permissions | `SHADOW_FILE_PERMISSIONS_SECURE`, `SSHD_CONFIG_PERMISSIONS_SECURE`, `DEMO_SENSITIVE_FILE_PERMISSIONS_SECURE` |
| Unsafe packages/services | `TELNET_PACKAGE_ABSENT`, `RSH_PACKAGE_ABSENT`, `FTP_SERVER_ABSENT` |
| Audit and logging | `AUDITD_INSTALLED`, `AUDITD_SERVICE_ENABLED`, `RSYSLOG_SERVICE_ACTIVE` |
| Time sync | `TIME_SYNC_ENABLED` |

Проверка `DEMO_SENSITIVE_FILE_PERMISSIONS_SECURE` использует `/tmp/demo-sensitive.txt`, чтобы совпадать с SCA policy и demo-сценарием.

## Package Vulnerability Checks

MVP-набор содержит 13 CVE-проверок по пакетам, типичным для Ubuntu Server 24.04 и текущего стенда.

| Rule ID | CVE | Packages | Severity |
| --- | --- | --- | --- |
| `VULN_OPENSSH_CVE_2024_6387` | `CVE-2024-6387` | `openssh-server` | high |
| `VULN_OPENSSH_CVE_2024_39894` | `CVE-2024-39894` | `openssh-client`, `openssh-server` | medium |
| `VULN_OPENSSL_CVE_2024_2511` | `CVE-2024-2511` | `libssl3t64`, `openssl` | medium |
| `VULN_OPENSSL_CVE_2024_4603` | `CVE-2024-4603` | `libssl3t64`, `openssl` | medium |
| `VULN_OPENSSL_CVE_2024_4741` | `CVE-2024-4741` | `libssl3t64`, `openssl` | high |
| `VULN_OPENSSL_CVE_2024_5535` | `CVE-2024-5535` | `libssl3t64`, `openssl` | medium |
| `VULN_OPENSSL_CVE_2024_6119` | `CVE-2024-6119` | `libssl3t64`, `openssl` | medium |
| `VULN_CURL_CVE_2024_7264` | `CVE-2024-7264` | `curl`, `libcurl4t64`, `libcurl3t64-gnutls` | medium |
| `VULN_CURL_CVE_2024_8096` | `CVE-2024-8096` | `curl`, `libcurl4t64`, `libcurl3t64-gnutls` | medium |
| `VULN_CURL_CVE_2024_9681` | `CVE-2024-9681` | `curl`, `libcurl4t64`, `libcurl3t64-gnutls` | medium |
| `VULN_SUDO_CVE_2025_32462` | `CVE-2025-32462` | `sudo` | high |
| `VULN_SUDO_CVE_2025_32463` | `CVE-2025-32463` | `sudo` | critical |
| `VULN_VIM_CVE_2024_47814` | `CVE-2024-47814` | `vim`, `vim-common` | medium |

Эти проверки не сканируют всю vulnerability-базу Wazuh. Exporter запрашивает только перечисленные `cve` из `profiles/host-baseline-v1.yml`, а затем дополнительно ограничивает findings по `packages`.

