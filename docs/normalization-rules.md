# Правила Нормализации Findings

## Обязательные Поля

Каждый finding в `artifacts/unified-findings.json` должен содержать:

- `host`
- `source`
- `category`
- `rule_id`
- `title`
- `severity`
- `status`
- `evidence`
- `remediation`

## Нормализация Severity

- `critical` -> `critical`
- `high` -> `high`
- `medium` -> `medium`
- `low` -> `low`
- неизвестные значения -> `medium`

## Нормализация Status

- baseline/SCA check passed -> `pass`
- baseline/SCA check failed -> `fail`
- служебное наблюдение без нарушения -> `info`
- неоднозначное или неполное состояние -> `warn`

## Дедупликация

Два findings считаются дублями, если совпадают:

- `host`
- `source`
- `category`
- `rule_id`

Если встречаются дубликаты с разными статусами, приоритет остаётся за `fail`.

## Разделение По Типам

- `configuration`: отклонения конфигурации хоста
- `software`: запрещённые или нежелательные пакеты
- `vulnerability`: CVE findings из Wazuh indexer
- `noise`: operational alerts, сохраняемые только как raw-артефакт

## Источники

- `wazuh_sca`: результаты `Wazuh API /sca/{agent_id}/checks/{policy_id}`
- `wazuh-api-syscollector`: сведения `Wazuh API /syscollector/{agent_id}/...`, используемые как вспомогательный raw-контекст
- raw operational alerts: экспортированный снимок `Wazuh API` и manager alerts

## Mapping SCA

Для SCA findings `scripts/export-findings.py` читает metadata из `profiles/host-baseline-v1.yml`:

- `sca_check_id` -> Wazuh SCA `id`;
- `id` -> итоговый `rule_id`;
- `title`, `category`, `severity`, `remediation` -> одноимённые поля finding.

Это означает, что при добавлении правила нужно синхронно обновить профиль и SCA policy. Явная таблица `check_id -> rule_id` в exporter больше не поддерживается вручную.

Текущий профиль добавляет 16 SCA checks:

| SCA ID | Rule ID | Категория | Severity |
| --- | --- | --- | --- |
| 10001 | `SSH_ROOT_LOGIN_DISABLED` | configuration | high |
| 10002 | `SSH_PASSWORD_AUTH_DISABLED` | configuration | high |
| 10003 | `SSH_EMPTY_PASSWORDS_DISABLED` | configuration | high |
| 10004 | `SSH_X11_FORWARDING_DISABLED` | configuration | medium |
| 10005 | `SSH_MAX_AUTH_TRIES_LIMITED` | configuration | medium |
| 10010 | `FIREWALL_UFW_ENABLED` | configuration | high |
| 10011 | `FIREWALL_DEFAULT_DENY_INCOMING` | configuration | high |
| 10020 | `SHADOW_FILE_PERMISSIONS_SECURE` | configuration | high |
| 10021 | `SSHD_CONFIG_PERMISSIONS_SECURE` | configuration | medium |
| 10030 | `TELNET_PACKAGE_ABSENT` | software | medium |
| 10031 | `RSH_PACKAGE_ABSENT` | software | medium |
| 10032 | `FTP_SERVER_ABSENT` | software | medium |
| 10040 | `AUDITD_INSTALLED` | configuration | medium |
| 10041 | `AUDITD_SERVICE_ENABLED` | configuration | medium |
| 10042 | `RSYSLOG_SERVICE_ACTIVE` | configuration | low |
| 10050 | `TIME_SYNC_ENABLED` | configuration | medium |
