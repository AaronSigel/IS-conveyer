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
- `noise`: operational alerts, сохраняемые только как raw-артефакт

## Источники

- `wazuh-api-sca`: результаты `Wazuh API /sca/{agent_id}/checks/{policy_id}`
- `wazuh-api-syscollector`: сведения `Wazuh API /syscollector/{agent_id}/...`, используемые как вспомогательный raw-контекст
- raw operational alerts: экспортированный снимок `Wazuh API` и manager alerts
