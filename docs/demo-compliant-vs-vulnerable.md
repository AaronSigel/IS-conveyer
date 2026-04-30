# Demo: Compliant vs Vulnerable Targets

## Назначение

Сценарий показывает, как один и тот же профиль ИБ `host-baseline-v1` различает два разных состояния серверов:

- `target1` - compliant / эталонный сервер.
- `target2` - vulnerable / сервер с намеренно внесёнными нарушениями.

Оба сервера проверяются одной Wazuh SCA policy. Разница в отчёте возникает только из-за состояния хостов, которое задаётся Ansible.

## Target1

`target1` приводится к compliant-состоянию:

- `PermitRootLogin no`
- `PasswordAuthentication no`
- UFW включён
- forbidden packages удалены
- `/tmp/demo-sensitive.txt` имеет права `0640`

## Target2

`target2` приводится к vulnerable-состоянию:

- `PermitRootLogin yes`
- `PasswordAuthentication yes`
- UFW выключен
- установлен forbidden package `telnet`
- `/tmp/demo-sensitive.txt` имеет права `0777`

## Запуск стенда

```bash
vagrant up
```

Если Wazuh ещё не подготовлен, сначала разверните manager и agents:

```bash
ansible-playbook -i ansible/inventories/lab.yml ansible/playbooks/wazuh.yml
```

Затем примените demo-состояния target-хостов:

```bash
ansible-playbook -i ansible/inventories/lab.yml ansible/playbooks/targets.yml
```

## Сканирование

```bash
python3 scripts/run-host-scan.py --hosts target1,target2
```

## Экспорт Findings

```bash
python3 scripts/export-findings.py
```

Результат сохраняется в:

```text
artifacts/unified-findings.json
```

## Генерация Отчёта

```bash
python3 scripts/generate-report.py
```

Markdown-отчёт сохраняется в:

```text
artifacts/draft-report.md
```

## Ожидаемый Результат

Для `target1` намеренные нарушения должны проходить как PASS:

- SSH root login disabled
- SSH password authentication disabled
- firewall enabled
- telnet absent
- secure permissions on `/tmp/demo-sensitive.txt`

Для `target2` в findings и отчёте должны появиться FAIL по тем же проверкам:

- SSH root login enabled
- SSH password authentication enabled
- firewall disabled
- telnet installed
- weak permissions on `/tmp/demo-sensitive.txt`

## Ручная Проверка

На `target1` ожидаются безопасные значения:

```bash
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config
sudo ufw status
dpkg -l | grep telnet
stat -c "%a" /tmp/demo-sensitive.txt
```

Ожидаемо:

```text
PermitRootLogin no
PasswordAuthentication no
ufw active
telnet отсутствует
640
```

На `target2` ожидаются уязвимые значения:

```text
PermitRootLogin yes
PasswordAuthentication yes
ufw inactive
telnet установлен
777
```

## Remediation

Чтобы вернуть все targets в compliant-состояние, используйте:

```bash
ansible-playbook -i ansible/inventories/lab.yml ansible/playbooks/remediate-targets.yml
```
