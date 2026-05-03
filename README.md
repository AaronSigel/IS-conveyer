# ib-host-audit-poc

Локальный PoC-стенд и отчётный конвейер для проверки хостов по профилю ИБ на базе `Vagrant`, `VirtualBox`, `Ansible` и `Wazuh`.

## Назначение

Wazuh используется как источник данных о состоянии конфигурации и уязвимостях установленного ПО. Проект реализует слой автоматизированной нормализации, дедупликации, группировки, приоритизации и формирования технического отчёта по результатам проверки требований информационной безопасности.

На текущем этапе проект подготавливает воспроизводимый инфраструктурный каркас, который:

- поднимает 3 виртуальные машины через `Vagrant`;
- настраивается `Ansible` с хоста;
- разворачивает `Wazuh manager`, `Wazuh agents`, `Wazuh API`, `Wazuh indexer` и `Wazuh dashboard`;
- включает встроенную Wazuh SCA policy `cis_ubuntu24-04`;
- проверяет CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0;
- позволяет автономно пройти путь от старта VM до `normalized_report.json`, HTML/PDF technical report и raw Wazuh snapshots.

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

Если PowerShell пишет, что выполнение `.\up.ps1` отключено политикой, вызовите **`.\scripts\windows\up.cmd`** (из `scripts\windows` — **`.\up.cmd`**): это тонкая обёртка над `powershell -ExecutionPolicy Bypass -File` и не требует менять `ExecutionPolicy`.

Подготовка WSL-окружения:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1
```

Полный запуск из Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Доступные Windows-обёртки (при политике `Restricted` удобнее **`.\scripts\windows\<имя>.cmd`**; иначе — явный вызов PowerShell ниже; см. [docs/windows-run.md](docs/windows-run.md)):

```bat
.\scripts\windows\bootstrap-wsl.cmd
.\scripts\windows\up.cmd
.\scripts\windows\provision.cmd
.\scripts\windows\smoke-test.cmd
.\scripts\windows\run-host-scan.cmd
.\scripts\windows\scan-and-report.cmd
.\scripts\windows\collect-report.cmd
.\scripts\windows\run-ui.cmd
.\scripts\windows\capture-state.cmd
.\scripts\windows\watch-state.cmd
.\scripts\windows\e2e.cmd
.\scripts\windows\destroy.cmd
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\up.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\smoke-test.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1 --hosts target1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\collect-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-ui.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\capture-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1 5
powershell -ExecutionPolicy Bypass -File .\scripts\windows\destroy.ps1
```

Подробная инструкция по подготовке Windows-окружения лежит в [docs/windows-run.md](docs/windows-run.md).

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

С хоста Windows те же шаги 1–4 (политика выполнения см. [docs/windows-run.md](docs/windows-run.md)):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\collect-report.ps1
```

`e2e.sh` поднимает VM, выполняет provisioning, запускает smoke test и формирует итоговые artifacts/отчёт одним вызовом.

```bash
./scripts/e2e.sh
./scripts/e2e.sh --hosts target1 --output-prefix target1-manual
./scripts/e2e.sh --skip-smoke-test --timeout 900
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1 --hosts target1 --output-prefix target1-manual
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1 -SkipSmokeTest --timeout 900
```

Покомпонентный режим остаётся доступен:

```bash
./scripts/up.sh
./scripts/provision.sh
./scripts/smoke-test.sh
./scripts/run-host-scan.py
./scripts/collect-report.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\up.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\smoke-test.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\collect-report.ps1
```

Сканирование хостов и сбор итоговых отчётов:

```bash
./scripts/scan-and-report.sh
./scripts/scan-and-report.sh --hosts target1 --output-prefix target1-manual
```

Основной результат современного pipeline сохраняется в run directory:

```text
artifacts/runs/<run_id>/
  metadata.json
  unified-findings.json
  normalized_report.json
  technical_report.html
  technical_report.pdf
  raw/
    wazuh-sca.json
    wazuh-vulnerabilities.json
```

`normalized_report.json` является главным контрактом отчёта. HTML и PDF являются представлениями этой модели; raw Wazuh snapshots сохраняются отдельно и не встраиваются в тело PDF. Для совместимости `--output-prefix` также оставляет prefixed копии старых artifacts в `artifacts/`.

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1 --hosts target1 --output-prefix target1-manual
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

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\capture-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1 5
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

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1 -e target_baseline_state=compliant
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
```

Вернуть targets к демонстрационным нарушениям:

```bash
./scripts/provision.sh -e target_baseline_state=drifting
./scripts/scan-and-report.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1 -e target_baseline_state=drifting
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
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
  --profile profiles/cis_ubuntu24-04.yml \
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

Подробности формата отчёта, роли шаблонов (`reporting/templates/*` как основной контур и `report/templates/*` как legacy compatibility), а также mapping `finding -> passport` описаны в [docs/report-format.md](docs/report-format.md).

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

С хоста Windows Web UI запускается **через локальный Python** (создаётся/используется `.venv` в корне репозитория; WSL не нужен):

```bat
.\scripts\windows\run-ui.cmd
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-ui.ps1
```

## Unified Python CLI

Основной Python CLI-контракт:

```bash
python -m is_conveyer export -- --hosts target1,target2
python -m is_conveyer report -- --findings artifacts/unified-findings.json --output artifacts/draft-report.md
python -m is_conveyer scan-and-report -- --hosts target1,target2
python -m is_conveyer run-ui --host 127.0.0.1 --port 8080 --reload
```

Старые `scripts/*.sh`, `scripts/windows/*.ps1`, `scripts/windows/*.cmd` сохранены как совместимые entrypoint-обёртки.

Дополнительные аргументы передаются в `uvicorn` (например `--port 8090`).

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

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\destroy.ps1
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

## Technical MVP report generator

A standalone GOST-like MVP report mode is available through `scripts/generate-report.py --format md|html`. It accepts a JSON file or a directory with Wazuh/unified JSON data, normalizes findings into one passport model, deduplicates package CVE records, excludes passed checks by default, and renders grouped Markdown/HTML reports.

Examples:

```bash
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/sample-technical-report.md --format md
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/sample-technical-report.html --format html --min-severity medium
python scripts/generate-report.py --input report/samples/wazuh-mvp --output report/full-technical-report.html --format html --include-passed --include-raw-appendix --include-low
```

Details: [docs/technical-mvp-report.md](docs/technical-mvp-report.md).
