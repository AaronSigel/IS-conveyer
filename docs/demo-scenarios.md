# Демонстрационные сценарии

## Сценарий 1. Поднятие стенда и подключение агентов

```bash
./scripts/e2e.sh --skip-smoke-test
```

Под Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1 -SkipSmokeTest
```

Ожидаемый результат:

- `Vagrant` создаёт и запускает `wazuh`, `target1`, `target2`;
- `Wazuh API` доступен на `https://192.168.56.10:55000`;
- `target1` и `target2` зарегистрированы как agents на manager.

## Сценарий 2. Initial scan и выгрузка findings

```bash
./scripts/scan-and-report.sh
```

Под Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
```

Ожидаемый результат:

- появляется `artifacts/unified-findings.json`;
- raw alerts сохраняются в `artifacts/raw-wazuh-alerts.json`;
- raw vulnerabilities сохраняются в `artifacts/raw-wazuh-vulnerabilities.json`;
- черновой отчёт сохраняется в `artifacts/draft-report.md`;
- findings формируются из `Wazuh API` и `Wazuh indexer`.
- SCA findings включают SSH hardening, firewall, file permissions, denylist packages, audit/logging и time sync.

Профиль можно проверить до запуска стенда:

```bash
python scripts/validate-profile.py profiles/host-baseline-v1.yml
```

Под Windows отдельной обёртки `.ps1` нет; выполните ту же команду внутри WSL из каталога репозитория.

## Сценарий 2a. Отдельный отчёт по выбранному хосту

```bash
./scripts/scan-and-report.sh --hosts target1 --output-prefix target1-manual
```

Под Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1 --hosts target1 --output-prefix target1-manual
```

Ожидаемый результат:

- появляется отдельный unified JSON `artifacts/target1-manual-unified-findings.json`;
- появляется отдельный vulnerability snapshot `artifacts/target1-manual-raw-wazuh-vulnerabilities.json`;
- появляется отдельный markdown-отчёт `artifacts/target1-manual-draft-report.md`;
- в артефактах присутствуют findings только по `target1`.

## Сценарий 3. Исправление нарушений и повторная проверка

```bash
./scripts/provision.sh -e target_baseline_state=compliant
./scripts/scan-and-report.sh
```

Под Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1 -e target_baseline_state=compliant
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
```

Ожидаемый результат:

- количество findings со статусом `fail` уменьшается;
- по исправленным правилам появляются `pass`;
- обновлённый markdown-отчёт отражает re-scan.

Сценарий `drifting`, который используется по умолчанию, намеренно включает:

- `PermitRootLogin yes`, `PasswordAuthentication yes`, `PermitEmptyPasswords yes`, `X11Forwarding yes`, `MaxAuthTries 6`;
- выключенный UFW;
- установку denylist-пакетов на отдельных targets;
- отсутствие `auditd`.

Сценарий `compliant` задаёт:

- `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `MaxAuthTries 4`;
- `ufw --force enable` и `ufw default deny incoming`;
- удаление telnet/rsh/FTP denylist-пакетов;
- установку и включение `auditd`, активный `rsyslog`, включённый `systemd-timesyncd`.

Вернуть targets в drifting-состояние можно явно:

```bash
./scripts/provision.sh -e target_baseline_state=drifting
./scripts/scan-and-report.sh
```

Под Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1 -e target_baseline_state=drifting
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
```

## Сценарий 4. Короткая демонстрация для защиты

1. Выполнить `./scripts/e2e.sh`.
2. Показать active agents и доступность manager.
3. Открыть `artifacts/draft-report.md`.
4. Показать `artifacts/unified-findings.json`.
5. Выполнить `./scripts/provision.sh -e target_baseline_state=compliant`.
6. Повторить `./scripts/scan-and-report.sh` и показать уменьшение числа `fail`.

Под Windows (шаги 1, 5 и 6; политика выполнения — [windows-run.md](windows-run.md)):

1. `powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1`
2. (без изменений)
3. (без изменений)
4. (без изменений)
5. `powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1 -e target_baseline_state=compliant`
6. `powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1`

## Сценарий 5. Запуск под Windows

Если политика выполнения блокирует `*.ps1`, из корня репозитория можно вызвать одноимённые **`*.cmd`** (например `.\scripts\windows\e2e.cmd`).

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Ожидаемый результат:

- Windows использует `WSL` как control-plane;
- `Vagrant` и `VirtualBox` работают на стороне Windows;
- итоговые артефакты появляются в каталоге `artifacts` репозитория;
- сценарий функционально повторяет Linux `./scripts/e2e.sh`.

Остальные сценарии (1–4) для Windows см. в блоках «Под Windows» выше; полный список обёртек — [windows-run.md](windows-run.md).
