# ib-host-audit-poc

Локальный PoC-стенд для проверки хостов по профилю ИБ на базе `Vagrant`, `VirtualBox` и `Ansible`.

## Назначение

На текущем этапе проект подготавливает воспроизводимый инфраструктурный каркас, который:

- поднимает 3 виртуальные машины через `Vagrant`;
- настраивается `Ansible` с хоста;
- остаётся чистым с точки зрения Git;
- уже включает облегчённый контур `Wazuh manager + agents + API + SCA + syscollector` для первого end-to-end цикла.

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

## Быстрый старт

```bash
./scripts/up.sh
./scripts/provision.sh
./scripts/smoke-test.sh
```

Проверенный сценарий запуска:

1. Поднять VM через `./scripts/up.sh`.
2. Применить конфигурацию через `./scripts/provision.sh`.
3. Проверить доступность узлов через `./scripts/smoke-test.sh`.
4. Запустить пользовательское сканирование и сбор отчёта через `./scripts/run-host-scan.py`.
5. При необходимости отдельно выгрузить findings через `python3 scripts/export-findings.py`.
6. Сгенерировать отчёт через `python3 scripts/generate-report.py`.

Сканирование хостов и сбор итоговых отчётов:

```bash
./scripts/run-host-scan.py
./scripts/run-host-scan.py --hosts target1 --output-prefix target1-manual
```

Что делает `run-host-scan.py`:

- инициирует новое сканирование выбранных хостов через перезапуск `wazuh-agent`;
- ждёт появления актуальных `SCA` и `syscollector` данных на manager;
- выгружает unified findings;
- сохраняет raw vulnerability snapshot из `Wazuh indexer`;
- формирует итоговый markdown-отчёт.

Сценарий повторной проверки после исправлений:

```bash
./scripts/provision.sh -e target_baseline_state=compliant
python3 scripts/export-findings.py
python3 scripts/generate-report.py
```

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

## Minimal Wazuh Profile

- На manager используется только `wazuh-manager` и `Wazuh API`.
- `wazuh-indexer`, `filebeat` и `wazuh-dashboard` не входят в обязательный рабочий контур и отключаются в lightweight-режиме.
- Findings для текущего PoC берутся из `Wazuh API`: `SCA` и `syscollector`.
- `vulnerability detection` в этом профиле отключён, чтобы не раздувать диск manager VM.
- В локальные artifacts экспортируются только API-реквизиты; dashboard-пароль в этом профиле не используется.

## Known Issues

- `VirtualBox` может выводить warning о несовпадении версии `Guest Additions` внутри box и версии хоста.
- На текущем PoC-стенде это предупреждение не блокирует `vagrant up`, provisioning и SSH-доступ.
- При проблемах с shared folders следует обновить box или переинициализировать VM под версию `VirtualBox`, установленную на хосте.
- В lightweight-режиме проект сознательно не поднимает полный стек `Wazuh indexer/dashboard`; проверка выполняется через `Wazuh API`, `SCA` и `syscollector`.
