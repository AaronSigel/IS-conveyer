# Legacy MVP Baseline Checks For Ubuntu 24.04

Документ фиксирует исторический состав кастомных проверок для MVP-демонстрации. Основной pipeline использует Wazuh CIS policy `cis_ubuntu24-04`, поэтому эти Rule IDs не должны попадать в основной SCA export.

## Configuration Checks

Кастомный набор configuration/SCA checks удалён из основного pipeline. Для демонстрации используется встроенный CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 policy `cis_ubuntu24-04`.

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

Эти проверки не сканируют всю vulnerability-базу Wazuh. CVE allowlist хранится в `profiles/cis_ubuntu24-04.yml` и используется только для package vulnerability findings, а не для SCA нормализации.

