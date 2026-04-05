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

    $resolved = (Resolve-Path $Path).Path
    $drive = $resolved.Substring(0, 1).ToLowerInvariant()
    $suffix = $resolved.Substring(2).Replace("\", "/")
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

    $linuxCommand = @(
        "set -euo pipefail"
        "export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS=1"
        "export VAGRANT_INSECURE_PRIVATE_KEY='$keyWslPath'"
        "mkdir -p '$wrapperDir'"
        "cat > '$wrapperDir/vagrant' <<'EOF'" + @"
#!/usr/bin/env bash
exec '$vagrantExeWslPath' "`$@"
"@ + "EOF"
        "chmod +x '$wrapperDir/vagrant'"
        "cat > '$wrapperDir/VBoxManage' <<'EOF'" + @"
#!/usr/bin/env bash
exec '$virtualBoxExeWslPath' "`$@"
"@ + "EOF"
        "chmod +x '$wrapperDir/VBoxManage'"
        ('export PATH="' + $wrapperDir + ':$PATH:' + $vagrantBinDir + ':' + $virtualBoxBinDir + '"')
        "cd '$repoWslPath'"
        $Command
    ) -join "; "

    Write-Host "[windows-wrapper] WSL distro: $resolvedDistro"
    Write-Host "[windows-wrapper] Repo path: $repoWslPath"
    Write-Host "[windows-wrapper] Command: $Command"

    & wsl.exe -d $resolvedDistro -- bash -lc $linuxCommand
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE."
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
