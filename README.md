# ib-host-audit-poc

Локальный PoC-стенд для проверки хостов по профилю ИБ на базе `Vagrant`, `VirtualBox` и `Ansible`.

## Назначение

На текущем этапе проект подготавливает воспроизводимый инфраструктурный каркас, который:

- поднимает 3 виртуальные машины через `Vagrant`;
- настраивается `Ansible` с хоста;
- остаётся чистым с точки зрения Git;
- готов к последующей интеграции `Wazuh`, `OpenSCAP`, `Trivy` и генерации отчётов.

## Зависимости

На хосте должны быть доступны:

- `git`
- `vagrant`
- `VBoxManage`
- `ansible`
- `ssh`

## Быстрый старт

```bash
./scripts/up.sh
./scripts/provision.sh
./scripts/smoke-test.sh
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
