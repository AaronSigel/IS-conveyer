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

Дополнительные поля для технического отчёта и паспортов уязвимостей являются необязательными. Старые findings без этих полей остаются допустимыми.

## Необязательные Поля Для Паспортов

- `finding_type`
- `vulnerability_id`
- `external_ids.cve`
- `external_ids.cwe`
- `external_ids.bdu`
- `cvss.base_score`
- `cvss.vector`
- `affected_component.name`
- `affected_component.version`
- `affected_component.package`
- `affected_component.service`
- `affected_component.port`
- `affected_component.protocol`
- `vulnerability_class`
- `weakness_id`
- `weakness_type`
- `location`
- `impact`
- `detected_at`
- `description`
- `os_platform`
- `detection_method`

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

## Mapping Vulnerabilities

Для vulnerability findings `scripts/export-findings.py` читает список `vulnerabilities` из `profiles/host-baseline-v1.yml`.

- `cve` используется как фильтр `vulnerability.id` в запросе к `wazuh-states-vulnerabilities*`;
- `packages`, если задан, дополнительно фильтрует `package.name`;
- `id`, `title`, `severity`, `remediation` становятся одноимёнными полями итогового finding.

Это ограничивает проверку только явно заданными в профиле CVE. Если список пустой, exporter не запрашивает vulnerability-базу Wazuh.

В отчёте такие findings преобразуются в паспорта типа `software_vulnerability`:

- класс уязвимости: `Уязвимость программного обеспечения`;
- CVE берётся из `external_ids.cve`, `cve`, `rule_id` или evidence;
- наименование ПО и версия берутся из `affected_component` или строки evidence `Package: ...`;
- CVSS берётся из `cvss.base_score` / `cvss.vector` или строки evidence `CVSS base: ...`;
- способ обнаружения: `Wazuh Vulnerability Detector`.

## Mapping SCA

Для SCA findings `scripts/export-findings.py` читает metadata из `profiles/host-baseline-v1.yml`:

- `sca_check_id` -> Wazuh SCA `id`;
- `id` -> итоговый `rule_id`;
- `title`, `category`, `severity`, `remediation` -> одноимённые поля finding.

Это означает, что при добавлении правила нужно синхронно обновить профиль и SCA policy. Явная таблица `check_id -> rule_id` в exporter больше не поддерживается вручную.

В отчёте SCA findings преобразуются в паспорта типа `configuration_noncompliance`, если тип не задан явно:

- CVSS: `не применимо`;
- способ обнаружения: `Wazuh SCA check <sca_check_id>` при наличии ID;
- metadata паспорта берётся из блока `passport` соответствующего правила профиля;
- при отсутствии passport metadata используются данные finding, затем безопасные fallback-значения.

Текущий профиль добавляет 17 SCA checks:

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
| 10022 | `DEMO_SENSITIVE_FILE_PERMISSIONS_SECURE` | configuration | medium |
| 10030 | `TELNET_PACKAGE_ABSENT` | software | medium |
| 10031 | `RSH_PACKAGE_ABSENT` | software | medium |
| 10032 | `FTP_SERVER_ABSENT` | software | medium |
| 10040 | `AUDITD_INSTALLED` | configuration | medium |
| 10041 | `AUDITD_SERVICE_ENABLED` | configuration | medium |
| 10042 | `RSYSLOG_SERVICE_ACTIVE` | configuration | low |
| 10050 | `TIME_SYNC_ENABLED` | configuration | medium |
