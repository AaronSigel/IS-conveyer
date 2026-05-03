# Формат профиля

Основной SCA pipeline больше не использует кастомный профиль правил. Для Ubuntu 24.04 он опирается на встроенную Wazuh policy `cis_ubuntu24-04` (`CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0`), а файл `profiles/cis_ubuntu24-04.yml` содержит только metadata для отчётов.

Legacy-профиль описывается YAML-файлом верхнего уровня со следующими блоками:

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

Удалённый legacy-профиль покрывал:

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
- `cvss`: необязательная CVSS metadata для отображения проверки даже при `pass`;
- `remediation`: направление исправления;
- `packages`: необязательный список пакетов. Если список задан, finding создаётся только для совпадающих `package.name`.

Пример:

```yaml
vulnerabilities:
  - id: VULN_CVE_2024_6387_OPENSSH
    cve: CVE-2024-6387
    title: OpenSSH regreSSHion CVE-2024-6387
    severity: critical
    cvss:
      base_score: 8.1
      vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
    remediation: Update OpenSSH packages to a fixed vendor version.
    packages:
      - openssh-server
```

Для `fail` exporter в первую очередь использует package/version и CVSS из документа Wazuh Indexer. Для `pass`, когда matching vulnerability document отсутствует, exporter использует `cve`, `packages` и `cvss` из профиля.

Если `vulnerabilities: []`, экспорт vulnerability snapshot пропускается и findings по всей базе Wazuh не создаются.

## Связь С Wazuh SCA

Для основного pipeline соответствие берётся из Wazuh CIS policy напрямую. Exporter опрашивает `/sca/{agent_id}/checks/cis_ubuntu24-04`, формирует `rule_id` как `cis_ubuntu24-04:<sca_check_id>` и не требует `compliance.custom`.

Текущий CIS metadata profile можно проверить локально:

```bash
python scripts/validate-profile.py profiles/cis_ubuntu24-04.yml
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

Для текущего Wazuh-only SCA pipeline authoritative mapping берётся из ответа Wazuh CIS policy, а не из legacy-профиля.

## Правила расширения

- использовать человекочитаемые идентификаторы правил;
- не смешивать в одной проверке несколько независимых требований;
- хранить ожидаемое состояние в декларативной форме;
- добавлять поля так, чтобы их можно было транслировать в разные движки проверок.
