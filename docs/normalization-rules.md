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

Дедупликация выполняется после преобразования raw findings в нормализованную модель.

Для `software_vulnerability` ключ дубля:

- `cve`
- `package.name`
- `package.installed_version`
- `package.fixed_condition`

Для `configuration_noncompliance` ключ дубля:

- `requirement.id`
- `check.command`
- `check.expected`

При совпадении ключа findings объединяются: `affected_assets`, `asset_details`, `raw_refs`, `evidence` и `package.installed_versions` агрегируются по активам.

## Remediation grouping

Remediation-группы не обязаны совпадать с ключами дедупликации.

Для пакетов базовый ключ - `package.name + fixed_condition`, но связанные пакеты могут объединяться в инженерную группу. Например, `openssl`, `libssl3`, `libssl-dev` группируются как `openssl`, а kernel-пакеты - как `ubuntu-kernel`.

Для конфигурации группировка выполняется по действию исправления, а не по CIS ID. Примеры групп:

- `aide`
- `core_dumps`
- `ssh`
- `pam`
- `auditd` и отдельные audit rules files
- `tmp_mount_options`
- `system_partitions`

Verification-команды берутся из `reporting/config/remediation_templates.yaml`. Если для действия нет локального шаблона, используется fallback по subsystem или исходная check-команда.

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

Для vulnerability findings `scripts/export-findings.py` читает список `vulnerabilities` из `profiles/cis_ubuntu24-04.yml`.

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

Для SCA findings `scripts/export-findings.py` читает checks из Wazuh policy `cis_ubuntu24-04`:

- Wazuh SCA `id` -> `sca_check_id`;
- `cis_ubuntu24-04:<id>` -> итоговый `rule_id`;
- `title`, `description`, `rationale`, `remediation`, `result`, `compliance` берутся из ответа Wazuh API;
- `agent.id`, `agent.name`, `agent.version` добавляются из `Wazuh API /agents`;
- `host.os.full`, `host.os.version`, `host.os.kernel` добавляются из `Wazuh API /syscollector/{agent_id}/os`;
- `category` фиксируется как `configuration`;
- `finding_type` фиксируется как `configuration_noncompliance`;
- при отсутствии severity exporter использует `medium`.

Custom allowlist для SCA checks не используется: в основной экспорт попадают все checks, которые вернул `/sca/{agent_id}/checks/cis_ubuntu24-04`.

В отчёте SCA findings преобразуются в паспорта типа `configuration_noncompliance`, если тип не задан явно:

- CVSS: `не применимо`;
- способ обнаружения: `Wazuh SCA check <sca_check_id>` при наличии ID;
- при отсутствии passport metadata используются данные finding, затем безопасные fallback-значения.
