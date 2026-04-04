# Архитектура PoC

## Компоненты

- `Vagrant` управляет жизненным циклом виртуальных машин.
- `VirtualBox` выступает основным provider.
- `Ansible` выполняет host-side provisioning и раскладку базовой конфигурации.
- `profiles/` хранит человекочитаемые профили ИБ.
- `report/` содержит каркас единого формата findings и шаблон отчёта.

## Поток данных

1. `Vagrantfile` описывает стенд и поднимает `wazuh`, `target1`, `target2`.
2. `ansible/inventory/hosts.ini` связывает VM с группами `wazuh` и `targets`.
3. `bootstrap.yml` готовит все узлы.
4. `targets.yml` раскладывает профили и демо-конфиги на целевые хосты.
5. В будущем findings будут нормализоваться в `report/schema/finding.schema.json`.

## Роль Vagrant

`Vagrant` обеспечивает одинаковый способ запуска стенда на Linux и Windows с одним и тем же `Vagrantfile`.

## Роль Ansible

`Ansible` отвечает за:

- базовую подготовку VM;
- установку минимальных пакетов;
- раскладку профилей и демонстрационных артефактов;
- каркас под будущий `Wazuh agent`.

## Точка будущей интеграции Wazuh

- группа `wazuh` зарезервирована под manager;
- роль `wazuh_agent` и playbook `wazuh.yml` содержат безопасный placeholder;
- IP менеджера уже описан в общих переменных Ansible.
