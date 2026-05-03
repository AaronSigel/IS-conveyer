# Demo scenario

Демонстрация показывает не замену Wazuh, а отчётный конвейер поверх Wazuh: сбор raw snapshots, нормализацию, дедупликацию, группировку, приоритизацию и формирование компактного технического отчёта.

## Drifting target

```bash
./scripts/provision.sh -e target_baseline_state=drifting
./scripts/scan-and-report.sh --hosts target1 --output-prefix drifting-demo
```

Ожидаемый результат: в `artifacts/runs/<run_id>/` создаются `metadata.json`, `unified-findings.json`, `normalized_report.json`, `technical_report.html`, `technical_report.pdf` при доступном PDF renderer, а также `raw/wazuh-sca.json` и `raw/wazuh-vulnerabilities.json`.

В отчёте нужно показать:

- asset inventory с Wazuh agent, OS, kernel, IP/status;
- remediation plan, отсортированный по P1-P4 priority score;
- группы конфигурационных несоответствий;
- группы уязвимостей пакетов, где один пакетный instance содержит список CVE;
- exceptions и under evaluation отдельно от remediation plan;
- raw artifacts как ссылки на отдельные JSON-файлы.

## Compliant target

```bash
./scripts/provision.sh -e target_baseline_state=compliant
./scripts/scan-and-report.sh --hosts target1 --output-prefix compliant-demo
```

Ожидаемый результат: отчёт создаётся даже при нулевом или малом числе active findings. Summary, remediation plan и verification checklist должны корректно показывать пустые значения без падения генератора.

## Web UI

```bash
python -m is_conveyer run-ui --host 127.0.0.1 --port 8080
```

Для демонстрации UI достаточно открыть список запусков, запустить scan-and-report, посмотреть статус и логи, затем скачать готовые `technical_report.html`, `technical_report.pdf`, `normalized_report.json` и raw artifacts из каталога запуска.
