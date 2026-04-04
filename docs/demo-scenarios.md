# Демонстрационные сценарии

## Сценарий 1. Поднятие стенда

```bash
./scripts/up.sh
```

Ожидаемый результат: `Vagrant` создаёт и запускает `wazuh`, `target1`, `target2`.

## Сценарий 2. Применение конфигурации

```bash
./scripts/provision.sh
```

Ожидаемый результат: `bootstrap.yml` подготавливает все VM, `targets.yml` настраивает целевые хосты, `wazuh.yml` отрабатывает как placeholder.

## Сценарий 3. Проверка доступности

```bash
./scripts/smoke-test.sh
```

Ожидаемый результат: VM видны `Vagrant`, доступны по `ssh`, команда `ansible all -m ping` проходит успешно.
