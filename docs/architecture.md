# Архитектура PoC

## Компоненты

- `Vagrant` управляет жизненным циклом виртуальных машин.
- `VirtualBox` выступает основным provider.
- `cloud-image/ubuntu-24.04` используется как актуальный базовый box для всех VM.
- `Ansible` выполняет host-side provisioning и раскладку базовой конфигурации.
- `profiles/` хранит metadata для отчётов и CVE allowlist, если он используется.
- `report/` содержит каркас единого формата findings и шаблон отчёта.
- `scripts/windows/` содержит PowerShell-обёртки для запуска Linux-сценариев проекта из `Windows` через `WSL`.

## Поток данных

1. `Vagrantfile` поднимает `wazuh`, `target1`, `target2`.
2. `bootstrap.yml` готовит ОС и базовые пакеты на всех VM.
3. `targets.yml` создаёт контролируемые нарушения или возвращает хосты в compliant-состояние.
4. `wazuh.yml` разворачивает `Wazuh manager`, `Wazuh agents`, `Wazuh API`, `Wazuh indexer` и `Wazuh dashboard`.
5. `scripts/run-host-scan.py` инициирует scan trigger и ждёт появления новых `SCA` и `syscollector` данных.
6. `scripts/export-findings.py` читает findings из `Wazuh API` и `Wazuh indexer`, затем нормализует результаты.
7. `scripts/generate-report.py` строит markdown-отчёт на основе `artifacts/unified-findings.json`.

## Роль Vagrant

`Vagrant` обеспечивает одинаковый способ запуска стенда на Linux и Windows с одним и тем же `Vagrantfile`.
На Windows orchestration выполняется через `WSL`, а запуск точек входа происходит PowerShell-обёртками из `scripts/windows/`. Из-за политики выполнения PowerShell в примерах используется вызов вида `powershell -ExecutionPolicy Bypass -File .\scripts\windows\…` (подробности в [windows-run.md](windows-run.md)).

## Роль Ansible

`Ansible` отвечает за:

- базовую подготовку VM;
- установку минимальных пакетов;
- раскладку профилей и демонстрационных артефактов;
- установку `Wazuh manager` и `Wazuh agent`;
- установку `Wazuh indexer` и `Wazuh dashboard`;
- включение встроенной Wazuh SCA policy `cis_ubuntu24-04` на агентах;
- переключение между drifting/compliant состояниями через `target_baseline_state`.

## Источники Findings

- `Wazuh API / SCA`: PASS/FAIL результаты CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 на агентах.
- `Wazuh API / syscollector`: сведения об ОС и установленном ПО на агентах.
- `Wazuh alerts`: operational и transport-события manager/agent, сохраняемые как raw-артефакт для отладки.
- `Wazuh indexer / vulnerabilities`: snapshot уязвимых пакетов, сохраняемый как raw-артефакт и используемый в unified findings.

## Типы Findings

- `configuration`: несоответствия, найденные Wazuh SCA policy `cis_ubuntu24-04`.
- `software`: findings по пакетам из Wazuh Vulnerability Detector или вспомогательных checks.
- `noise`: operational alerts, которые не попадают в итоговый unified JSON, но сохраняются как raw-артефакт для отладки.

## Основная SCA Policy

Основной pipeline использует встроенную policy Wazuh `cis_ubuntu24-04` (`ruleset/sca/ubuntu/cis_ubuntu24-04.yml`). Exporter не применяет кастомный allowlist SCA rules и нормализует checks напрямую из ответа `Wazuh API /sca/{agent_id}/checks/cis_ubuntu24-04`.

## Known Issues

- При старте VM `VirtualBox` может сообщать о несовпадении `Guest Additions` в box и версии хоста.
- Для текущего PoC это предупреждение не блокирует подъем стенда, SSH-подключения и выполнение `Ansible`.
- Базовый проверенный путь запуска: `./scripts/e2e.sh`.
- На Windows требуется согласованная работа `WSL`, Windows `Vagrant` и Windows `VirtualBox` в одном каталоге проекта.
