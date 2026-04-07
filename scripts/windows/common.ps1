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
    $candidates = @(
        (Join-Path $HOME ".vagrant.d\insecure_private_keys\vagrant.key.rsa"),
        (Join-Path $HOME ".vagrant.d\insecure_private_keys\vagrant.key.ed25519"),
        (Join-Path $HOME ".vagrant.d\insecure_private_key")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Vagrant insecure private key was not found in '$HOME\.vagrant.d'."
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
    if ($command) {
        return $command.Source
    }

    if ($CommandName -ieq "VBoxManage.exe" -or $CommandName -ieq "VBoxManage") {
        $registryKeys = @(
            "HKLM:\SOFTWARE\Oracle\VirtualBox",
            "HKLM:\SOFTWARE\WOW6432Node\Oracle\VirtualBox"
        )

        foreach ($key in $registryKeys) {
            $installDir = (Get-ItemProperty $key -ErrorAction SilentlyContinue).InstallDir
            if (-not $installDir) {
                continue
            }

            $candidate = Join-Path $installDir "VBoxManage.exe"
            if (Test-Path $candidate) {
                return (Resolve-Path $candidate).Path
            }
        }

        $fallbackPaths = @(
            "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            "C:\Program Files\VirtualBox\VBoxManage.exe"
        )

        foreach ($candidate in $fallbackPaths) {
            if (Test-Path $candidate) {
                return (Resolve-Path $candidate).Path
            }
        }
    }

    throw "'$CommandName' is not available on Windows PATH."
}

function Ensure-VirtualBoxHostOnlyAdapter {
    param(
        [string]$IpAddress = "192.168.56.1",
        [string]$NetworkMask = "255.255.255.0"
    )

    $vboxManage = Get-WindowsCommandPath -CommandName "VBoxManage.exe"
    $hostOnlyInfo = & $vboxManage list hostonlyifs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to list VirtualBox host-only interfaces."
    }

    $interfaceNames = @(
        $hostOnlyInfo |
            Select-String '^Name:\s+(.+)$' |
            ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
    )

    if (-not $interfaceNames) {
        Write-Host "[windows-wrapper] Creating VirtualBox host-only adapter"
        & $vboxManage hostonlyif create | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create VirtualBox host-only interface."
        }

        $hostOnlyInfo = & $vboxManage list hostonlyifs
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to list VirtualBox host-only interfaces after creation."
        }

        $interfaceNames = @(
            $hostOnlyInfo |
                Select-String '^Name:\s+(.+)$' |
                ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
        )
    }

    $interfaceName = $interfaceNames | Where-Object { $_ -eq "VirtualBox Host-Only Ethernet Adapter" } | Select-Object -First 1
    if (-not $interfaceName) {
        $interfaceName = $interfaceNames | Select-Object -First 1
    }

    if (-not $interfaceName) {
        throw "VirtualBox host-only interface could not be resolved."
    }

    Write-Host "[windows-wrapper] Using host-only adapter: $interfaceName"
    & $vboxManage hostonlyif ipconfig $interfaceName --ip $IpAddress --netmask $NetworkMask | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure VirtualBox host-only interface '$interfaceName'."
    }

    return $interfaceName
}

function Invoke-WindowsVagrant {
    param(
        [string[]]$Arguments = @(),
        [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    )

    $vagrantExe = Get-WindowsCommandPath -CommandName "vagrant.exe"
    Push-Location $RepoRoot
    try {
        & $vagrantExe @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Vagrant command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
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
export WINDOWS_HOST_IP="$(ip route show default | awk '/default/ { print $3; exit }')"

WRAPPER_DIR=__WRAPPER_DIR__
VIRTUALBOX_BIN_DIR=__VIRTUALBOX_BIN_DIR__
WINDOWS_KEY_PATH=__KEY_WSL_PATH__
WSL_VAGRANT_KEY=/tmp/is-conveyer-vagrant.key
mkdir -p "$WRAPPER_DIR"
cp "$WINDOWS_KEY_PATH" "$WSL_VAGRANT_KEY"
chmod 600 "$WSL_VAGRANT_KEY"
export VAGRANT_INSECURE_PRIVATE_KEY="$WSL_VAGRANT_KEY"

cat > "$WRAPPER_DIR/vagrant" <<'EOF'
#!/usr/bin/env bash
PATH="$PATH:/mnt/c/Windows/System32" exec cmd.exe /c vagrant.exe "$@"
EOF
chmod +x "$WRAPPER_DIR/vagrant"

cat > "$WRAPPER_DIR/VBoxManage" <<'EOF'
#!/usr/bin/env bash
PATH="$PATH:/mnt/c/Windows/System32" exec cmd.exe /c VBoxManage.exe "$@"
EOF
chmod +x "$WRAPPER_DIR/VBoxManage"

export PATH="$WRAPPER_DIR:$PATH:$VIRTUALBOX_BIN_DIR"
cd __REPO_WSL_PATH__
__COMMAND__
'@

    $linuxScript = $linuxScriptTemplate
    $linuxScript = $linuxScript.Replace("__KEY_WSL_PATH__", (Quote-ForBash -Value $keyWslPath))
    $linuxScript = $linuxScript.Replace("__WRAPPER_DIR__", (Quote-ForBash -Value $wrapperDir))
    $linuxScript = $linuxScript.Replace("__VIRTUALBOX_BIN_DIR__", (Quote-ForBash -Value $virtualBoxBinDir))
    $linuxScript = $linuxScript.Replace("__REPO_WSL_PATH__", (Quote-ForBash -Value $repoWslPath))
    $linuxScript = $linuxScript.Replace("__COMMAND__", $Command)
    $linuxScript = $linuxScript.Replace("`r`n", "`n").Replace("`r", "`n")

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
    $parts.Add("bash")
    $parts.Add((Quote-ForBash -Value $ScriptPath))

    foreach ($arg in $Arguments) {
        $parts.Add((Quote-ForBash -Value $arg))
    }

    Invoke-InWslRepo -Distro $Distro -RepoRoot $RepoRoot -Command ($parts -join " ")
}
