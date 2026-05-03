# Формат технического отчёта

Главный контракт современного отчёта - `normalized_report.json`. HTML и PDF являются представлением этой нормализованной модели, а raw-данные Wazuh сохраняются рядом отдельными артефактами и не встраиваются в тело PDF.

Legacy markdown-отчёт с паспортами сохраняется для совместимости через `scripts/generate-report.py --mode legacy`, но MVP-артефактами считаются:

- `metadata.json`
- `unified-findings.json`
- `normalized_report.json`
- `technical_report.html`
- `technical_report.pdf`
- `raw/wazuh-sca.json`
- `raw/wazuh-vulnerabilities.json`

CLI `scripts/scan-and-report.sh --output-prefix <prefix>` создаёт новый каталог запуска в `artifacts/runs/<run_id>/` и оставляет prefixed копии в `artifacts/` для совместимости со старыми командами.

## Структура `normalized_report.json`

```text
report_id
generated_at
run
scope.assets
summary
remediation_plan
remediation_groups
findings
under_evaluation
raw_refs
```

`findings` содержит основные активные findings после фильтрации, дедупликации и исключения `pass`/`under_evaluation`. `under_evaluation` хранится отдельно и не попадает в remediation plan. `raw_refs` нужен для трассировки, но не печатается в PDF.

`priority` является внутренним приоритетом P1-P4 и дополняется полями `priority_score` и `priority_reason`. Remediation plan сортируется по `priority_score`, а не только по Wazuh severity.

## Структура HTML/PDF

Технический HTML/PDF строится из `reporting/templates/technical_report.html` и содержит:

1. Run summary
2. Asset inventory
3. Risk and findings summary
4. План устранения / Top remediation actions
5. Configuration remediation groups
6. Software vulnerability groups
7. Verification checklist
8. Exceptions and under evaluation
9. Ограниченный набор паспортных finding cards в `summary` или полный набор в `full`
10. Raw artifacts note

Таблица remediation plan содержит только короткие поля: priority, group, severity, assets, findings и summary. Полные commands, verification и rollback выводятся в карточках remediation-групп. Полный JSON и raw Wazuh snapshots должны скачиваться отдельными файлами, а не вставляться в PDF.

`summary` является режимом по умолчанию и не печатает весь список detailed finding cards. `full` может включать все карточки и длинные evidence/remediation/compliance поля.

```bash
python scripts/generate-report.py --mode summary
python scripts/generate-report.py --mode full
python scripts/generate-report.py --mode legacy
```

## Asset inventory

Инвентаризация активов строится из `asset_details` нормализованных findings. Для SCA findings exporter добавляет данные Wazuh agent и syscollector OS, чтобы поля `agent.id`, `agent.version`, `host.os.full`, `host.os.version`, `host.os.kernel` заполнялись тем же способом, что и для vulnerability findings.

`unknown` допустим только если исходные Wazuh API/indexer данные действительно не содержат соответствующего поля.

## Фильтры

`scripts/generate-report.py` поддерживает фильтры:

- `--status`
- `--severity`
- `--category`
- `--source`
- `--host`
- `--rule-id`
- `--finding-type`
- `--cvss-min`
- `--cvss-max`

Фильтры со списками принимают значения через запятую. Если после фильтрации findings не осталось, отчёт всё равно создаётся, но remediation plan и finding cards остаются пустыми.

## Legacy markdown

Legacy markdown-режим формирует разделы 0-6 и паспорта findings в стиле старого технического отчёта. Он не является источником истины для MVP HTML/PDF и не должен использоваться для описания структуры `normalized_report.json`.

## Template roles

- `reporting/templates/*` — основной MVP pipeline для technical HTML/PDF, который строится из `normalized_report.json`.
- `report/templates/*` — legacy markdown compatibility для режима `scripts/generate-report.py --mode legacy`.

Новые изменения в шаблонах отчёта должны вноситься в `reporting/templates/*`. Добавлять третью параллельную ветку шаблонов нельзя.
