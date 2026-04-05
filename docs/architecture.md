# Архитектура PoC

## Компоненты

- `Vagrant` управляет жизненным циклом виртуальных машин.
- `VirtualBox` выступает основным provider.
- `cloud-image/ubuntu-24.04` используется как актуальный базовый box для всех VM.
- `Ansible` выполняет host-side provisioning и раскладку базовой конфигурации.
- `profiles/` хранит человекочитаемые профили ИБ.
- `report/` содержит каркас единого формата findings и шаблон отчёта.

## Поток данных

1. `Vagrantfile` поднимает `wazuh`, `target1`, `target2`.
2. `bootstrap.yml` готовит ОС и базовые пакеты на всех VM.
3. `targets.yml` создаёт контролируемые нарушения или возвращает хосты в compliant-состояние.
4. `wazuh.yml` разворачивает облегчённый `Wazuh manager` и агентов, а baseline SCA policy раскладывается на target-хосты напрямую через Ansible.
5. `scripts/export-findings.py` читает findings напрямую из `Wazuh API` и нормализует результаты `SCA` и `syscollector`.
6. Нормализованные findings сохраняются в `artifacts/unified-findings.json` и далее используются генератором отчёта.
7. В lightweight-режиме assistant config рендерится только для `wazuh-server`, без узлов `indexer` и `dashboard`.

## Роль Vagrant

`Vagrant` обеспечивает одинаковый способ запуска стенда на Linux и Windows с одним и тем же `Vagrantfile`.

## Роль Ansible

`Ansible` отвечает за:

- базовую подготовку VM;
- установку минимальных пакетов;
- раскладку профилей и демонстрационных артефактов;
- установку `Wazuh manager` и `Wazuh agent`;
- прямую доставку исполняемой SCA policy на агенты;
- переключение между drifting/compliant состояниями через `target_baseline_state`.
- перевод manager в lightweight-профиль без обязательных `indexer/dashboard/filebeat`.

## Источники Findings

- `Wazuh API / SCA`: PASS/FAIL результаты исполняемой baseline policy на агентах.
- `Wazuh API / syscollector`: сведения об ОС и установленном ПО на агентах.
- `Wazuh alerts`: operational и transport-события manager/agent, сохраняемые как raw-артефакт для отладки.

## Типы Findings

- `configuration`: настройки SSH, firewall и права на чувствительный файл.
- `software`: запрещённые пакеты из baseline-профиля.
- `noise`: operational alerts, которые не попадают в итоговый unified JSON, но сохраняются как raw-артефакт для отладки.

## Соответствие Профиля И Исполняемой Policy

- `ssh-permit-root-login-disabled` -> SCA check `10001`
- `ssh-password-authentication-disabled` -> SCA check `10002`
- `package-telnet-absent` -> SCA check `10003`
- `firewall-enabled` -> SCA check `10004`
- `sensitive-file-permissions-restricted` -> SCA check `10005`
- `denylist.packages` / `rsh-redone-client` -> SCA check `10006`

## Known Issues

- При старте VM `VirtualBox` может сообщать о несовпадении `Guest Additions` в box и версии хоста.
- Для текущего PoC это предупреждение не блокирует подъем стенда, SSH-подключения и выполнение `Ansible`.
- Базовый проверенный путь запуска: `./scripts/up.sh` -> `./scripts/provision.sh` -> `./scripts/smoke-test.sh`.
- Полный стек `indexer/dashboard/filebeat` сознательно исключён из обязательного контура, чтобы не тратить диск manager VM на ненужные для PoC сервисы.
- Manager-side shared groups для custom SCA в этом PoC нестабильны, поэтому baseline policy раскладывается на агенты напрямую. Это сознательный компромисс в пользу воспроизводимости.
