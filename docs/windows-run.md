# Запуск Проекта Под Windows

## Назначение

Этот документ описывает, как запускать проект на `Windows` без переноса control-plane логики в сами VM.

Текущая модель такая:

- `Vagrant` и `VirtualBox` работают на стороне Windows;
- orchestration и host-side tooling выполняются внутри `WSL`;
- PowerShell-скрипты из `scripts/windows/` вызывают Linux-скрипты проекта внутри `WSL`.

## Требования

На Windows-хосте должны быть установлены:

- `WSL`
- `Ubuntu` в качестве WSL-дистрибутива
- `Vagrant`
- `VirtualBox`
- `Git`

Внутри `WSL` должны быть доступны:

- `bash`
- `python3`
- `ansible`
- `ssh`
- `curl`

## Важные Ограничения

- Репозиторий должен лежать на Windows-диске, а не только внутри файловой системы `WSL`.
- Windows `Vagrant` и `WSL` должны работать с одним и тем же каталогом проекта.
- Скрипты автоматически выставляют `VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1`.
- Путь к `Vagrant insecure_private_key` автоматически пробрасывается из Windows в `WSL` через `VAGRANT_INSECURE_PRIVATE_KEY`.

## Подготовка Окружения

Один раз выполните:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1
```

Что делает этот скрипт:

- проверяет наличие `wsl.exe`;
- проверяет наличие `vagrant.exe` и `VBoxManage.exe`;
- находит WSL-дистрибутив `Ubuntu`;
- устанавливает внутри `WSL` пакеты `ansible`, `python3`, `openssh-client`, `git`, `curl`.

Если нужно использовать другой WSL-дистрибутив:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1 -Distro Ubuntu-24.04
```

## Основные Точки Входа

Полный end-to-end запуск:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Отдельные сценарии:

```powershell
.\scripts\windows\up.ps1
.\scripts\windows\provision.ps1
.\scripts\windows\smoke-test.ps1
.\scripts\windows\run-host-scan.ps1 --hosts target1
.\scripts\windows\scan-and-report.ps1
.\scripts\windows\collect-report.ps1
.\scripts\windows\capture-state.ps1
.\scripts\windows\watch-state.ps1 5
.\scripts\windows\destroy.ps1
```

## Соответствие Linux И Windows Скриптов

| Windows | Linux |
| --- | --- |
| `scripts/windows/e2e.ps1` | `scripts/e2e.sh` |
| `scripts/windows/up.ps1` | `scripts/up.sh` |
| `scripts/windows/provision.ps1` | `scripts/provision.sh` |
| `scripts/windows/smoke-test.ps1` | `scripts/smoke-test.sh` |
| `scripts/windows/run-host-scan.ps1` | `scripts/run-host-scan.py` |
| `scripts/windows/scan-and-report.ps1` | `scripts/scan-and-report.sh` |
| `scripts/windows/collect-report.ps1` | `scripts/collect-report.sh` |
| `scripts/windows/capture-state.ps1` | `scripts/capture-state.sh` |
| `scripts/windows/watch-state.ps1` | `scripts/watch-state.sh` |
| `scripts/windows/destroy.ps1` | `scripts/destroy.sh` |

## Рекомендуемый Путь Запуска

1. Выполнить `bootstrap-wsl.ps1`.
2. Запустить `e2e.ps1`.
3. Дождаться завершения provisioning, smoke test и scan/report pipeline.
4. Открыть итоговые артефакты в каталоге `artifacts/`.

## Результат Успешного Запуска

После успешного запуска должны появиться:

- `artifacts/unified-findings.json`
- `artifacts/raw-wazuh-alerts.json`
- `artifacts/raw-wazuh-vulnerabilities.json`
- `artifacts/draft-report.md`

## Диагностика

Если запуск не проходит:

- проверьте, что `wsl.exe -l -q` показывает нужный дистрибутив;
- проверьте, что `vagrant.exe` и `VBoxManage.exe` доступны из PowerShell;
- убедитесь, что проект открыт с Windows-диска;
- выполните `.\scripts\windows\capture-state.ps1`;
- при длительном provisioning запустите `.\scripts\windows\watch-state.ps1 5`.

## Известные Особенности

- Первый cold-start на Windows может занимать заметно больше времени, чем повторный запуск.
- `VirtualBox` может предупреждать о несовпадении версии `Guest Additions`; для текущего PoC это не обязательно является блокером.
- Реальная логика развёртывания по-прежнему выполняется Linux-скриптами проекта, а PowerShell-слой является только Windows launcher-обвязкой.
