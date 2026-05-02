# Запуск Проекта Под Windows

## Назначение

Этот документ описывает, как запускать проект на `Windows` без переноса control-plane логики в сами VM.

Текущая модель такая:

- `Vagrant` и `VirtualBox` работают на стороне Windows;
- orchestration и host-side tooling выполняются внутри `WSL`;
- PowerShell-скрипты из `scripts/windows/` вызывают Linux-скрипты проекта внутри `WSL`.
- исключение: **`run-ui.ps1` / `run-ui.cmd`** поднимают Web UI через **установленный в Windows Python** (`py -3` или `python` в `PATH`), создают/используют каталог `.venv` в корне репозитория и не ходят в WSL. Если `.venv` раньше создавали только в WSL (там каталог `bin/`, а не `Scripts/`), обёртка пересоздаст окружение под Windows.

## Требования

На Windows-хосте должны быть установлены:

- `WSL`
- `Ubuntu` в качестве WSL-дистрибутива
- `Vagrant`
- `VirtualBox`
- `Git`
- `Python` для Windows (для Web UI: лаунчер `py.exe` или `python.exe` в `PATH`)

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
- устанавливает внутри `WSL` пакеты `ansible`, `python3`, `python3-venv` (нужен для `run-ui.sh` и других сценариев с `python3 -m venv`), `openssh-client`, `git`, `curl`.

Если нужно использовать другой WSL-дистрибутив:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1 -Distro Ubuntu-24.04
```

## Политика Выполнения PowerShell

Прямой запуск вида `.\scripts\windows\*.ps1` на многих системах блокируется политикой по умолчанию (сообщение вроде «выполнение сценариев отключено»). Ниже все примеры используют обход только для выбранного процесса.

**Самый простой обход без смены политики:** рядом с каждой точкой входа лежит одноимённый `*.cmd`, который вызывает `powershell -ExecutionPolicy Bypass -File` за вас. Из корня репозитория:

```bat
.\scripts\windows\up.cmd
```

Из каталога `scripts\windows` (как вы пытались с `.\up.ps1`):

```bat
.\up.cmd
```

Аргументы передаются дальше в `.ps1` (например `.\scripts\windows\watch-state.cmd 5`).

Альтернатива один раз для текущего пользователя (если это допустимо в вашей среде):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

После этого обычно можно вызывать `.\scripts\windows\*.ps1` без префикса `powershell -ExecutionPolicy Bypass -File`.

## Основные Точки Входа

Полный end-to-end запуск:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1
```

Отдельные сценарии (все команды из корня репозитория на Windows-диске):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\up.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\provision.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\smoke-test.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-host-scan.ps1 --hosts target1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\scan-and-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\collect-report.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\run-ui.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\capture-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1 5
powershell -ExecutionPolicy Bypass -File .\scripts\windows\destroy.ps1
```

## Соответствие Linux И Windows Скриптов

| Windows | Linux |
| --- | --- |
| `scripts/windows/bootstrap-wsl.ps1` | подготовка WSL (один раз; прямого аналога в `scripts/*.sh` нет) |
| `scripts/windows/e2e.ps1` | `scripts/e2e.sh` |
| `scripts/windows/up.ps1` | `scripts/up.sh` |
| `scripts/windows/provision.ps1` | `scripts/provision.sh` |
| `scripts/windows/smoke-test.ps1` | `scripts/smoke-test.sh` |
| `scripts/windows/run-host-scan.ps1` | `scripts/run-host-scan.py` |
| `scripts/windows/scan-and-report.ps1` | `scripts/scan-and-report.sh` |
| `scripts/windows/collect-report.ps1` | `scripts/collect-report.sh` |
| `scripts/windows/run-ui.ps1` | `scripts/run-ui.sh` |
| `scripts/windows/capture-state.ps1` | `scripts/capture-state.sh` |
| `scripts/windows/watch-state.ps1` | `scripts/watch-state.sh` |
| `scripts/windows/destroy.ps1` | `scripts/destroy.sh` |

У каждой перечисленной `*.ps1` в `scripts/windows/` есть одноимённый **`*.cmd`**, который подходит для запуска при блокировке политикой выполнения PowerShell.

## Рекомендуемый Путь Запуска

1. Выполнить `powershell -ExecutionPolicy Bypass -File .\scripts\windows\bootstrap-wsl.ps1`.
2. Запустить `powershell -ExecutionPolicy Bypass -File .\scripts\windows\e2e.ps1`.
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
- выполните `powershell -ExecutionPolicy Bypass -File .\scripts\windows\capture-state.ps1`;
- при длительном provisioning запустите `powershell -ExecutionPolicy Bypass -File .\scripts\windows\watch-state.ps1 5`.
- если вы запускаете **`./scripts/run-ui.sh` внутри WSL** и создание `.venv` падает с `ensurepip is not available`, в WSL выполните `sudo apt-get install -y python3-venv` (или `.\scripts\windows\bootstrap-wsl.cmd`); при необходимости удалите повреждённый `.venv`. С **`run-ui.cmd` / `run-ui.ps1` в Windows** используется Python с хоста, эта ошибка из WSL не относится.
- если `run-ui` открывает не тот UI или `/` возвращает `500`, проверьте, что порт `8080` не занят старым `uvicorn`: `Get-NetTCPConnection -LocalPort 8080 -State Listen | Select-Object OwningProcess`. Новая версия `run-ui.ps1` проверяет это при запуске и показывает PID/команду; альтернативно запустите UI на другом порту: `.\scripts\windows\run-ui.cmd --port 8090`.

## Известные Особенности

- Первый cold-start на Windows может занимать заметно больше времени, чем повторный запуск.
- `VirtualBox` может предупреждать о несовпадении версии `Guest Additions`; для текущего PoC это не обязательно является блокером.
- Реальная логика развёртывания по-прежнему выполняется Linux-скриптами проекта, а PowerShell-слой является только Windows launcher-обвязкой.
