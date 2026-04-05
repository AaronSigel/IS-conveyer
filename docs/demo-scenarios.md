# Демонстрационные сценарии

## Сценарий 1. Поднятие стенда и подключение агентов

```bash
./scripts/up.sh
./scripts/provision.sh
```

Ожидаемый результат:

- `Vagrant` создаёт и запускает `wazuh`, `target1`, `target2`;
- `Wazuh API` доступен на `https://192.168.56.10:55000`;
- `target1` и `target2` зарегистрированы как active agents.

## Сценарий 2. Initial scan и выгрузка findings

```bash
./scripts/run-host-scan.py
```

Ожидаемый результат:

- появляется `artifacts/unified-findings.json`;
- raw alerts сохраняются в `artifacts/raw-wazuh-alerts.json`;
- raw vulnerabilities сохраняются в `artifacts/raw-wazuh-vulnerabilities.json`;
- черновой отчёт сохраняется в `artifacts/draft-report.md`;
- findings формируются из `Wazuh API` и `Wazuh indexer`.

## Сценарий 2a. Отдельный отчёт по выбранному хосту

```bash
./scripts/run-host-scan.py --hosts target1 --output-prefix target1-manual
```

Ожидаемый результат:

- появляется отдельный unified JSON `artifacts/target1-manual-unified-findings.json`;
- появляется отдельный vulnerability snapshot `artifacts/target1-manual-raw-wazuh-vulnerabilities.json`;
- появляется отдельный markdown-отчёт `artifacts/target1-manual-draft-report.md`;
- в артефактах присутствуют findings только по `target1`.

## Сценарий 3. Исправление нарушений и повторная проверка

```bash
./scripts/provision.sh -e target_baseline_state=compliant
./scripts/run-host-scan.py
```

Ожидаемый результат:

- количество findings со статусом `fail` уменьшается;
- по исправленным правилам появляются `pass`;
- обновлённый markdown-отчёт отражает re-scan.

## Сценарий 4. Короткая демонстрация для защиты

1. Выполнить `./scripts/up.sh` и `./scripts/provision.sh`.
2. Показать active agents и доступность manager.
3. Выполнить `./scripts/run-host-scan.py`.
4. Открыть `artifacts/unified-findings.json` и `artifacts/draft-report.md`.
5. Выполнить `./scripts/provision.sh -e target_baseline_state=compliant`.
6. Повторить `./scripts/run-host-scan.py` и показать уменьшение числа `fail`.
