# ib-host-audit-poc

Локальный PoC-стенд для проверки хостов по профилю ИБ на базе `Vagrant`, `VirtualBox`, `Ansible` и `Wazuh`.

## Назначение

На текущем этапе проект подготавливает воспроизводимый инфраструктурный каркас, который:

- поднимает 3 виртуальные машины через `Vagrant`;
- настраивается `Ansible` с хоста;
- разворачивает `Wazuh manager`, `Wazuh agents`, `Wazuh API`, `Wazuh indexer` и `Wazuh dashboard`;
- доставляет custom Wazuh SCA policy `host-baseline-v1`;
- проверяет расширенный профиль Ubuntu 24.04: SSH hardening, UFW firewall, права файлов, denylist-пакеты, audit/logging и time sync;
- позволяет автономно пройти путь от старта VM до готового markdown-отчёта.

## Зависимости

На хосте должны быть доступны:

- `git`
- `vagrant`
- `VBoxManage`
- `ansible`
- `ssh`

Проверенная базовая конфигурация стенда:

- provider: `VirtualBox`
- Vagrant box: `cloud-image/ubuntu-24.04`
- хостовая ОС разработки: Linux

## Windows Host

Для запуска на Windows используйте `WSL` как Linux control-plane, а `Vagrant` и `VirtualBox` оставляйте на стороне Windows.

Подготовка WSL-окружения:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1
```

Полный запуск из Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Доступные Windows-обёртки:

```powershell
.\scripts\windows\up.ps1
.\scripts\windows\provision.ps1
.\scripts\windows\smoke-test.ps1
.\scripts\windows\run-host-scan.ps1 --hosts target1
.\scripts\windows\scan-and-report.ps1
.\scripts\windows\collect-report.ps1
.\scripts\windows\capture-state.ps1
.\scripts\windows\watch-state.ps1 5
.\scripts\windows\destroy.ps1
```

Подробная инструкция по подготовке Windows-окружения лежит в [docs/windows-run.md](/home/funder/IS-project/docs/windows-run.md).

Текущая модель Windows-запуска опирается на:
- установленный `WSL`-дистрибутив `Ubuntu`;
- установленные в Windows `Vagrant` и `VirtualBox`;
- запуск репозитория с Windows-диска, чтобы `WSL` и Windows `Vagrant` работали с одними и теми же файлами;
- `VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1`, который выставляется скриптом автоматически.

## Быстрый старт

```bash
./scripts/e2e.sh
```

Для Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Проверенный сценарий запуска:

1. Запустить полный автономный цикл через `./scripts/e2e.sh`.
2. При необходимости повторно запускать только scan/report-контур через `./scripts/scan-and-report.sh`.
3. При необходимости отдельно запускать scan trigger через `./scripts/run-host-scan.py`.
4. При необходимости отдельно выгружать findings и собирать отчёт через `./scripts/collect-report.sh`.

`e2e.sh` поднимает VM, выполняет provisioning, запускает smoke test и формирует итоговые artifacts/отчёт одним вызовом.

```bash
./scripts/e2e.sh
./scripts/e2e.sh --hosts target1 --output-prefix target1-manual
./scripts/e2e.sh --skip-smoke-test --timeout 900
```

Покомпонентный режим остаётся доступен:

```bash
./scripts/up.sh
./scripts/provision.sh
./scripts/smoke-test.sh
python scripts/validate-profile.py profiles/host-baseline-v1.yml
./scripts/run-host-scan.py
./scripts/collect-report.sh
```

Сканирование хостов и сбор итоговых отчётов:

```bash
./scripts/scan-and-report.sh
./scripts/scan-and-report.sh --hosts target1 --output-prefix target1-manual
```

Что делает `run-host-scan.py`:

- инициирует новое сканирование выбранных хостов через перезапуск `wazuh-agent`;
- ждёт появления актуальных `SCA` и `syscollector` данных на manager.

Что делает `scan-and-report.sh`:

- запускает scan trigger;
- ждёт готовности новых данных;
- вызывает сбор findings и генерацию отчёта.

Что делает `collect-report.sh`:

- выгружает unified findings;
- сохраняет raw vulnerability snapshot из `Wazuh indexer`;
- формирует итоговый технический markdown-отчёт с паспортами уязвимостей и несоответствий.

Наблюдение за состоянием стенда во время `provision` или `run-host-scan`:

```bash
./scripts/capture-state.sh
./scripts/watch-state.sh
./scripts/watch-state.sh 5
```

`capture-state.sh` делает разовый снимок:
- `vagrant status`
- загрузка дисков на manager
- статусы `wazuh-manager/indexer/filebeat/dashboard`
- хвосты `wazuh-install.log` и `ossec.log`
- наличие и состояние `wazuh-agent` на `target1/target2`

`watch-state.sh` повторяет этот снимок по кругу с интервалом в секундах.

Сценарий повторной проверки после исправлений:

```bash
./scripts/provision.sh -e target_baseline_state=compliant
./scripts/scan-and-report.sh
```

Вернуть targets к демонстрационным нарушениям:

```bash
./scripts/provision.sh -e target_baseline_state=drifting
./scripts/scan-and-report.sh
```

Итоговые данные:

- `artifacts/unified-findings.json`: нормализованные findings;
- `artifacts/raw-wazuh-alerts.json`: raw Wazuh API snapshot;
- `artifacts/raw-wazuh-vulnerabilities.json`: raw Wazuh indexer vulnerability snapshot;
- `artifacts/draft-report.md`: технический markdown-отчёт.

## Технический отчёт

Генератор отчёта формирует компактный технический отчёт по результатам проверки защищённости хостов. Основной результат отчёта - раздел `5 ПАСПОРТА ВЫЯВЛЕННЫХ УЯЗВИМОСТЕЙ И НЕСООТВЕТСТВИЙ`; каждый включённый finding представлен отдельным паспортом с описанием, доказательством, последствиями и возможными мерами устранения.

Отчёт не содержит титульный лист, реферат, содержание, приложения, сводную таблицу findings и отдельный remediation plan. Сводка считается только по findings, прошедшим фильтрацию.

Пример генерации:

```bash
python scripts/generate-report.py \
  --findings artifacts/unified-findings.json \
  --profile profiles/host-baseline-v1.yml \
  --metadata config/report-metadata.yml \
  --output report/technical-report.md \
  --status failed \
  --severity high,critical
```

Поддерживаемые фильтры:

- `--status`
- `--severity`
- `--category`
- `--source`
- `--host`
- `--rule-id`
- `--finding-type`
- `--cvss-min`
- `--cvss-max`

Подробности формата отчёта и mapping `finding -> passport` описаны в [docs/report-format.md](/home/funder/IS-project/docs/report-format.md).

## Web UI

### Предусловия

- VM уже подняты.
- Wazuh manager доступен.
- Wazuh agents активны.
- Существующий scan pipeline работает из CLI.

### Запуск

```bash
./scripts/run-ui.sh
```

### Адрес

```text
http://127.0.0.1:8080
```

### Возможности

- запуск проверки;
- просмотр логов;
- история запусков;
- фильтрация отчёта;
- экспорт HTML/PDF.

## Удаление стенда

```bash
./scripts/destroy.sh
```

## Структура проекта

```text
.
├── Vagrantfile
├── ansible/
├── docs/
├── profiles/
├── report/
├── scripts/
└── artifacts/
```

Подробности по архитектуре, формату профилей и демонстрационным сценариям лежат в [docs/architecture.md](/home/funder/IS-project/docs/architecture.md), [docs/profile-format.md](/home/funder/IS-project/docs/profile-format.md) и [docs/demo-scenarios.md](/home/funder/IS-project/docs/demo-scenarios.md).
Правила нормализации findings описаны в [docs/normalization-rules.md](/home/funder/IS-project/docs/normalization-rules.md).

## Known Issues

- `VirtualBox` может выводить warning о несовпадении версии `Guest Additions` внутри box и версии хоста.
- На текущем PoC-стенде это предупреждение не блокирует `vagrant up`, provisioning и SSH-доступ.
- При проблемах с shared folders следует обновить box или переинициализировать VM под версию `VirtualBox`, установленную на хосте.
- Полный cold-start `e2e` может занимать заметное время, так как manager устанавливает `Wazuh server`, `indexer` и `dashboard` с нуля.
