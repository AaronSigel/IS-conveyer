param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$venvDir = Join-Path $RepoRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

function Invoke-CreateVenv {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        & py.exe -3 -m venv $venvDir
        if ($LASTEXITCODE -ne 0) {
            throw "py -3 -m venv завершился с кодом $LASTEXITCODE."
        }
        return
    }
    $pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        & $pythonCmd.Source -m venv $venvDir
        if ($LASTEXITCODE -ne 0) {
            throw "python -m venv завершился с кодом $LASTEXITCODE."
        }
        return
    }
    throw "Python не найден. Установите Python с https://www.python.org/ (с лаунчером py.exe) либо добавьте python.exe в PATH."
}

function Get-UvicornOptions {
    $port = 8080
    $remaining = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $ScriptArgs.Count; $i++) {
        $arg = $ScriptArgs[$i]
        if ($arg -eq "--port" -and ($i + 1) -lt $ScriptArgs.Count) {
            $port = [int]$ScriptArgs[$i + 1]
            $i++
            continue
        }
        if ($arg -like "--port=*") {
            $port = [int]$arg.Substring("--port=".Length)
            continue
        }
        $remaining.Add($arg)
    }
    return @{
        Port = $port
        Args = [string[]]$remaining
    }
}

function Assert-PortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if (-not $listeners) {
        return
    }

    $details = foreach ($listener in $listeners) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
        if ($process) {
            "PID $($listener.OwningProcess): $($process.CommandLine)"
        }
        else {
            "PID $($listener.OwningProcess)"
        }
    }
    throw "Порт $Port уже занят. Остановите старый Web UI/uvicorn или запустите с другим портом: .\run-ui.cmd --port 8090`n$($details -join "`n")"
}

Push-Location $RepoRoot
try {
    if ((Test-Path -LiteralPath $venvDir) -and -not (Test-Path -LiteralPath $venvPython)) {
        Write-Host "[run-ui] Каталог .venv без Windows-интерпретатора (часто после создания в WSL). Пересоздаём .venv для Windows."
        Remove-Item -LiteralPath $venvDir -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $venvPython)) {
        Invoke-CreateVenv
    }
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Не удалось создать виртуальное окружение в .venv"
    }

    $requirements = Join-Path $RepoRoot "requirements-ui.txt"
    & $venvPython -m pip install -r $requirements
    if ($LASTEXITCODE -ne 0) {
        throw "pip install завершился с кодом $LASTEXITCODE."
    }
    & $venvPython -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        throw "playwright install завершился с кодом $LASTEXITCODE."
    }

    $options = Get-UvicornOptions
    Assert-PortAvailable -Port $options.Port

    $uvicornArgs = @(
        "web.app:app",
        "--host", "127.0.0.1",
        "--port", ([string]$options.Port),
        "--reload"
    )
    if ($options.Args.Count -gt 0) {
        $uvicornArgs += $options.Args
    }
    & $venvPython -m uvicorn @uvicornArgs
}
finally {
    Pop-Location
}
