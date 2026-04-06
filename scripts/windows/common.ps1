Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-WslDistroName {
    param(
        [string]$Distro = "Ubuntu"
    )

    $distros = wsl.exe -l -q | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($distros -contains $Distro) {
        return $Distro
    }

    $candidate = $distros | Where-Object { $_ -like "$Distro*" } | Select-Object -First 1
    if ($candidate) {
        return $candidate
    }

    throw "WSL distro '$Distro' is not installed."
}

function Convert-WindowsPathToWsl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $candidate = $Path
    if (Test-Path $Path) {
        $candidate = (Resolve-Path $Path).Path
    }

    if ($candidate.Length -lt 3 -or $candidate[1] -ne ':') {
        throw "Path '$Path' is not a valid Windows path."
    }

    $drive = $candidate.Substring(0, 1).ToLowerInvariant()
    $suffix = $candidate.Substring(2).Replace("\", "/")
    return "/mnt/$drive$suffix"
}

function Get-VagrantKeyWindowsPath {
    $candidate = Join-Path $HOME ".vagrant.d\insecure_private_key"
    if (-not (Test-Path $candidate)) {
        throw "Vagrant insecure private key was not found at '$candidate'."
    }
    return (Resolve-Path $candidate).Path
}

function Quote-ForBash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return "'" + $Value.Replace("'", "'\''") + "'"
}

function Get-WindowsCommandPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName
    )

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "'$CommandName' is not available on Windows PATH."
    }

    return $command.Source
}

function Invoke-InWslRepo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [string]$Distro = "Ubuntu",
        [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    )

    $resolvedDistro = Get-WslDistroName -Distro $Distro
    $repoWslPath = Convert-WindowsPathToWsl -Path $RepoRoot
    $keyWslPath = Convert-WindowsPathToWsl -Path (Get-VagrantKeyWindowsPath)
    $vagrantExeWslPath = Convert-WindowsPathToWsl -Path (Get-WindowsCommandPath -CommandName "vagrant.exe")
    $virtualBoxExeWslPath = Convert-WindowsPathToWsl -Path (Get-WindowsCommandPath -CommandName "VBoxManage.exe")
    $vagrantBinDir = Split-Path $vagrantExeWslPath -Parent
    $virtualBoxBinDir = Split-Path $virtualBoxExeWslPath -Parent
    $wrapperDir = "/tmp/is-conveyer-windows-bin"
    $scriptFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("is-conveyer-" + [System.Guid]::NewGuid().ToString("N") + ".sh"))
    $scriptFileWslPath = Convert-WindowsPathToWsl -Path $scriptFile

    $linuxScriptTemplate = @'
#!/usr/bin/env bash
set -euo pipefail

export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1
export VAGRANT_INSECURE_PRIVATE_KEY=__KEY_WSL_PATH__

WRAPPER_DIR=__WRAPPER_DIR__
VAGRANT_BIN_DIR=__VAGRANT_BIN_DIR__
VIRTUALBOX_BIN_DIR=__VIRTUALBOX_BIN_DIR__
mkdir -p "$WRAPPER_DIR"

cat > "$WRAPPER_DIR/vagrant" <<'EOF'
#!/usr/bin/env bash
exec __VAGRANT_EXE_WSL_PATH__ "$@"
EOF
chmod +x "$WRAPPER_DIR/vagrant"

cat > "$WRAPPER_DIR/VBoxManage" <<'EOF'
#!/usr/bin/env bash
exec __VIRTUALBOX_EXE_WSL_PATH__ "$@"
EOF
chmod +x "$WRAPPER_DIR/VBoxManage"

export PATH="$WRAPPER_DIR:$PATH:$VAGRANT_BIN_DIR:$VIRTUALBOX_BIN_DIR"
cd __REPO_WSL_PATH__
__COMMAND__
'@

    $linuxScript = $linuxScriptTemplate
    $linuxScript = $linuxScript.Replace("__KEY_WSL_PATH__", (Quote-ForBash -Value $keyWslPath))
    $linuxScript = $linuxScript.Replace("__WRAPPER_DIR__", (Quote-ForBash -Value $wrapperDir))
    $linuxScript = $linuxScript.Replace("__VAGRANT_BIN_DIR__", (Quote-ForBash -Value $vagrantBinDir))
    $linuxScript = $linuxScript.Replace("__VIRTUALBOX_BIN_DIR__", (Quote-ForBash -Value $virtualBoxBinDir))
    $linuxScript = $linuxScript.Replace("__VAGRANT_EXE_WSL_PATH__", (Quote-ForBash -Value $vagrantExeWslPath))
    $linuxScript = $linuxScript.Replace("__VIRTUALBOX_EXE_WSL_PATH__", (Quote-ForBash -Value $virtualBoxExeWslPath))
    $linuxScript = $linuxScript.Replace("__REPO_WSL_PATH__", (Quote-ForBash -Value $repoWslPath))
    $linuxScript = $linuxScript.Replace("__COMMAND__", $Command)

    Write-Host "[windows-wrapper] WSL distro: $resolvedDistro"
    Write-Host "[windows-wrapper] Repo path: $repoWslPath"
    Write-Host "[windows-wrapper] Command: $Command"

    try {
        [System.IO.File]::WriteAllText($scriptFile, $linuxScript, [System.Text.UTF8Encoding]::new($false))
        & wsl.exe -d $resolvedDistro -- bash $scriptFileWslPath
        if ($LASTEXITCODE -ne 0) {
            throw "WSL command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        if (Test-Path $scriptFile) {
            Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-WslScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [string]$Distro = "Ubuntu",
        [string[]]$Arguments = @(),
        [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add($ScriptPath)

    foreach ($arg in $Arguments) {
        $parts.Add((Quote-ForBash -Value $arg))
    }

    Invoke-InWslRepo -Distro $Distro -RepoRoot $RepoRoot -Command ($parts -join " ")
}
