# MVP reporting audit

Дата проверки: 2026-05-03.

## Проверенные команды

```bash
python scripts/generate-report.py --help
python scripts/export-findings.py --help
bash ./scripts/scan-and-report.sh --hosts target1 --output-prefix audit-before
bash ./scripts/e2e.sh --hosts target1 --output-prefix audit-before
```

`generate-report.py --help` работает. Текущий CLI поддерживает режимы `technical` и `legacy`, вывод `normalized_report.json`, HTML, PDF, split reports, legacy markdown и фильтры по status, severity, category, source, host, rule-id, finding-type и CVSS.

`export-findings.py --help` работает. Текущий CLI поддерживает `--output`, `--raw-alerts-output`, `--raw-vulns-output`, `--hosts`.

`scan-and-report.sh` успешно прошёл для `target1` и создал плоские prefixed artifacts в `artifacts/`:

- `audit-before-unified-findings.json`
- `audit-before-raw-wazuh-alerts.json`
- `audit-before-raw-wazuh-vulnerabilities.json`
- `audit-before-normalized_report.json`
- `audit-before-technical_report.html`
- `audit-before-draft-report.md`

PDF не был создан, потому что в текущем окружении не найден Playwright или headless Chrome/Edge. Генератор корректно продолжил работу и оставил JSON/HTML artifacts.

`e2e.sh` не прошёл на этом хосте: `vagrant: command not found`. Это ограничение окружения запуска, а не отчётного pipeline.

## Фактическая структура artifacts

При `--output-prefix` текущий pipeline пишет файлы в плоский `artifacts/`, а raw snapshots называются `*-raw-wazuh-alerts.json` и `*-raw-wazuh-vulnerabilities.json`.

При `--output-dir` `collect-report.sh` уже близок к целевому contract и пишет:

```text
<output-dir>/
  unified-findings.json
  draft-report.md
  normalized_report.json
  technical_report.html
  technical_report.pdf
  raw/
    wazuh-sca.json
    wazuh-vulnerabilities.json
```

Отдельная run-scoped структура `artifacts/runs/<run_id>/` сейчас создаётся Web UI в `web/runs.py`, но CLI с `--output-prefix` сам её не создаёт.

## Основная логика отчёта

- `scripts/export-findings.py` получает данные Wazuh API/indexer, сохраняет raw snapshots и формирует `unified-findings.json`.
- `reporting/normalizers/wazuh_sca.py` и `reporting/normalizers/wazuh_vulnerabilities.py` приводят Wazuh records к unified findings.
- `scripts/generate-report.py` вызывает `reporting.services.report_export.build_normalized_report_for_export`.
- `reporting/builder.py` строит `normalized_report.json`: нормализация, дедупликация, applicability, priorities, remediation groups, asset inventory.
- `reporting/templates/technical_report.html` является основным HTML/PDF template для MVP ветки.
- `web/jobs.py` запускает `scan-and-report.sh --output-dir`, а `web/runs.py` ведёт run directories.

## Найденные gaps

- `--output-prefix` не создаёт целевую папку `artifacts/runs/<run_id>/`.
- `metadata.json` для CLI run сейчас не создаётся.
- `report_id` в CLI technical mode сейчас фиксирован как `default`.
- В `normalized_report.json` raw refs содержат embedded raw data; для PDF это не печатается, но модель раздувается.
- Summary HTML/PDF печатает все detailed finding cards, из-за чего отчёт похож на raw export.
- Package vulnerability groups сейчас агрегируются по package family/fixed condition, а не по конкретному package instance.
- `priority` сейчас строка `P1`-`P4`; нет `priority_score` и `priority_reason`.
- Asset inventory теряет доступные поля. Raw Wazuh agents содержат `ip`, `status`, `version`; syscollector OS содержит `os.name`, `os.version`, `release`, `architecture`, но SCA normalizer читает только плоские поля и поэтому часть значений становится `unknown` или kernel build string вместо нормального OS.
- Web UI запускает pipeline, но часть страниц всё ещё пересчитывает preview/export по `unified-findings.json`, а не показывает только готовые artifacts.
