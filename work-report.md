# Work Report

## Контекст

Проект `ib-host-audit-poc` доведён до рабочего PoC-стенда на базе `Vagrant`, `VirtualBox` и `Ansible` с минимализированным контуром `Wazuh`.

Текущий целевой профиль:

- `wazuh-manager`
- `Wazuh API`
- `wazuh-agent` на `target1` и `target2`
- `SCA`
- `syscollector`

Из обязательного рабочего контура сознательно исключены:

- `wazuh-indexer`
- `filebeat`
- `wazuh-dashboard`
- `vulnerability detection`
- `syscheck`

## Что реализовано

### 1. Базовый инфраструктурный каркас

- Поднят локальный стенд с 3 VM: `wazuh`, `target1`, `target2`.
- Настроены `Vagrantfile`, inventory, playbook'и и роли `Ansible`.
- Подготовлены управляющие скрипты:
  - `scripts/up.sh`
  - `scripts/provision.sh`
  - `scripts/smoke-test.sh`
  - `scripts/destroy.sh`

### 2. Контролируемый baseline/drift сценарий

- Реализован baseline-профиль хостов.
- Поддерживаются два состояния:
  - `drifting`
  - `compliant`
- В роль target baseline добавлены проверки и remediation для:
  - `PermitRootLogin`
  - `PasswordAuthentication`
  - firewall
  - прав на чувствительный файл
  - forbidden packages (`telnet`, `rsh-redone-client`)
- Исправлен кейс с потерей SSH после `ufw`: теперь перед compliant-настройкой разрешается `OpenSSH`.

### 3. Wazuh manager и agents

- Развёрнут manager с API.
- Агенты `target1` и `target2` регистрируются и видны на manager.
- Custom SCA policy доставляется на агенты напрямую через `Ansible`.
- Для агентов включены:
  - `SCA`
  - `syscollector`
- Для агентов отключён `syscheck`.
- Для manager в lightweight-режиме отключены:
  - vulnerability detection
  - indexer integration
  - manager-side syscheck

### 4. Минимализация Wazuh

- Manager-role переведена в lightweight-профиль.
- В minimal-path больше не выполняются install/config шаги для:
  - `wazuh-indexer`
  - `wazuh-dashboard`
  - keystore-коннектора к indexer
  - ожидания портов `9200` и `443`
- После provisioning тяжёлые сервисы принудительно выключаются и disable'ятся.
- Очищаются тяжёлые runtime-очереди Wazuh.
- Assistant config в lightweight-режиме рендерится только для `wazuh-server`.
- Из project-level vars удалены неиспользуемые `dashboard/indexer` переменные.

### 5. Экспорт findings из Wazuh API

- Реализован экспортёр `scripts/export-findings.py`.
- Экспортёр работает именно через `Wazuh API`.
- Используемые API endpoints:
  - `/security/user/authenticate`
  - `/agents`
  - `/sca/{agent_id}/checks/host-baseline-v1`
  - `/syscollector/{agent_id}/os`
  - `/syscollector/{agent_id}/packages`
- Результаты нормализуются в unified JSON.
- Реализованы:
  - schema validation
  - deduplication
  - evidence/remediation fields
  - raw artifact export

### 6. Отчётность и артефакты

- Реализован генератор отчёта `scripts/generate-report.py`.
- Подготовлены:
  - unified findings
  - raw alerts snapshot
  - raw vulnerabilities snapshot
  - markdown draft report
- В lightweight-профиле локально сохраняются только API-реквизиты.
- Dashboard password artifact больше не используется и очищается.

### 7. Документация

Обновлены и синхронизированы с текущей реализацией:

- `README.md`
- `docs/architecture.md`
- `docs/demo-scenarios.md`
- `docs/normalization-rules.md`
- milestone и report template файлы из предыдущих этапов

## Текущее рабочее состояние

### Manager

- Активен `wazuh-manager`
- API доступен на `https://192.168.56.10:55000`

### Heavy services

В lightweight-профиле не требуются и должны оставаться выключенными:

- `wazuh-indexer`
- `filebeat`
- `wazuh-dashboard`

### Agents

- `target1` и `target2` регистрируются как active agents
- На агентах выполняется custom policy `host-baseline-v1`

## Подтверждённые проверки

В ходе работы успешно проходили:

- `vagrant validate`
- `ansible-playbook --syntax-check`
- `ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/wazuh.yml --limit wazuh`
- `python3 -m py_compile scripts/export-findings.py scripts/generate-report.py`
- `python3 scripts/export-findings.py`
- `python3 scripts/generate-report.py`
- `./scripts/smoke-test.sh`

Дополнительно подтверждено:

- manager видит агентов через `agent_control -l`
- экспортёр получает данные через Wazuh API
- compliant re-scan даёт нулевой fail по двум target-хостам

## Подтверждённый результат compliant-сценария

Для текущего compliant-состояния подтверждался результат:

- `target1`: `fail=0`, `pass=6`
- `target2`: `fail=0`, `pass=6`

Артефакты:

- `artifacts/unified-findings-compliant.json`
- `artifacts/draft-report-compliant.md`
- `artifacts/raw-wazuh-alerts-compliant.json`
- `artifacts/raw-wazuh-vulnerabilities-compliant.json`

## Локальные секреты и служебные файлы

Актуальный локальный credentials-файл:

- `artifacts/wazuh-credentials.env`

Содержит только:

- `WAZUH_MANAGER_IP`
- `WAZUH_API_URL`
- `WAZUH_API_USER`
- `WAZUH_API_PASSWORD`

## Известные ограничения

### 1. Vulnerability detection

Нативный `Wazuh vulnerability detection` отключён. Причина: в рамках текущей VM manager этот контур раздувает диск и приводит к ошибкам вида `database or disk is full`.

### 2. Full Wazuh stack

Проект не использует полный стек `indexer/dashboard/filebeat` как обязательную часть PoC. Это осознанное упрощение ради стабильности и воспроизводимости.

### 3. VirtualBox warning

Возможен warning о несовпадении `Guest Additions` внутри box и версии хоста. На текущий PoC это не влияло критически.

## Ключевые файлы реализации

Инфраструктура и orchestration:

- `Vagrantfile`
- `ansible/playbooks/targets.yml`
- `ansible/playbooks/wazuh.yml`
- `ansible/group_vars/all.yml`

Wazuh manager:

- `ansible/roles/wazuh_manager/tasks/main.yml`
- `ansible/roles/wazuh_manager/defaults/main.yml`
- `ansible/roles/wazuh_manager/templates/config.yml.j2`

Wazuh agent:

- `ansible/roles/wazuh_agent/tasks/main.yml`
- `ansible/roles/wazuh_agent/defaults/main.yml`
- `ansible/roles/wazuh_agent/templates/host-baseline-v1-sca.yml.j2`

Baseline and remediation:

- `ansible/roles/target_baseline/tasks/main.yml`
- `profiles/host-baseline-v1.yml`

Экспорт и отчёты:

- `scripts/export-findings.py`
- `scripts/generate-report.py`
- `scripts/smoke-test.sh`
- `report/templates/report-template.md`

Документация:

- `README.md`
- `docs/architecture.md`
- `docs/demo-scenarios.md`
- `docs/normalization-rules.md`

## Вывод

На текущий момент проект находится в рабочем состоянии для PoC-задачи host audit:

- стенд воспроизводим локально;
- controlled drift/remediation работает;
- findings экспортируются из `Wazuh API`;
- markdown-отчёт генерируется;
- минимальный профиль `Wazuh` стабилизирован и не зависит от `indexer/dashboard`.
