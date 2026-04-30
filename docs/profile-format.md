# Формат профиля

Профиль описывается YAML-файлом верхнего уровня со следующими блоками:

- `profile`: идентификатор и версия профиля;
- `metadata`: назначение, владелец и комментарии;
- `checks`: список проверок;
- `vulnerabilities`: список CVE, которые нужно учитывать из Wazuh indexer;
- `denylist` или `allowlist`: дополнительные ограничения по пакетам и сервисам.

## Структура проверки

Каждая проверка содержит:

- `id`: стабильный идентификатор правила;
- `title`: короткое название;
- `category`: категория finding, сейчас используются `configuration` и `software`;
- `severity`: уровень критичности, допустимы `critical`, `high`, `medium`, `low`, `info`;
- `rationale`: почему контроль важен;
- `remediation`: направление исправления;
- `sca_check_id`: числовой id соответствующего Wazuh SCA check.

Профиль `host-baseline-v1` покрывает:

- SSH hardening: root login, password authentication, empty passwords, X11 forwarding, MaxAuthTries;
- firewall: активный UFW и default deny incoming;
- file permissions: `/etc/shadow` и `/etc/ssh/sshd_config`;
- denylist packages: telnet, rsh, FTP-серверы;
- audit/logging: auditd и rsyslog;
- time synchronization: timedatectl, chrony или systemd-timesyncd.

## Структура Vulnerability-Проверки

Wazuh indexer хранит все найденные CVE в индексах `wazuh-states-vulnerabilities*`, но экспортёр учитывает только CVE из раздела `vulnerabilities`.

Каждая vulnerability-проверка содержит:

- `id`: стабильный идентификатор правила;
- `cve`: CVE ID, например `CVE-2024-6387`;
- `title`: короткое название finding;
- `severity`: уровень критичности, допустимы `critical`, `high`, `medium`, `low`, `info`;
- `remediation`: направление исправления;
- `packages`: необязательный список пакетов. Если список задан, finding создаётся только для совпадающих `package.name`.

Пример:

```yaml
vulnerabilities:
  - id: VULN_CVE_2024_6387_OPENSSH
    cve: CVE-2024-6387
    title: OpenSSH regreSSHion CVE-2024-6387
    severity: critical
    remediation: Update OpenSSH packages to a fixed vendor version.
    packages:
      - openssh-server
```

Если `vulnerabilities: []`, экспорт vulnerability snapshot пропускается и findings по всей базе Wazuh не создаются.

## Связь С Wazuh SCA

Каждое правило профиля имеет пару в SCA policy `host-baseline-v1-sca.yml`. В `compliance.custom` SCA check указывается `id` правила из профиля, а `sca_check_id` профиля совпадает с `id` SCA check.

Перед запуском стенда профиль можно проверить локально:

```bash
python scripts/validate-profile.py profiles/host-baseline-v1.yml
```

Smoke-check проверяет:

- YAML читается;
- `id` правил уникальны;
- `sca_check_id` уникальны;
- `vulnerabilities[].id` и `vulnerabilities[].cve` уникальны;
- `category` и `severity` входят в допустимые enum;
- обязательные поля заполнены.

## Наследие MVP

Ранние версии профиля также использовали поля:

- `description`: смысл проверки;
- `target`: объект контроля;
- `expected`: ожидаемое состояние;
- `severity`: уровень критичности;
- `remediation`: направление исправления.

Для текущего Wazuh-only pipeline authoritative mapping берётся из `id`, `category`, `severity`, `remediation` и `sca_check_id`.

## Правила расширения

- использовать человекочитаемые идентификаторы правил;
- не смешивать в одной проверке несколько независимых требований;
- хранить ожидаемое состояние в декларативной форме;
- добавлять поля так, чтобы их можно было транслировать в разные движки проверок.
