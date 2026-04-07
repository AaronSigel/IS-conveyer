param(
    [string]$Distro = "Ubuntu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe is not available. Install WSL first."
}

if (-not (Get-Command vagrant.exe -ErrorAction SilentlyContinue)) {
    throw "vagrant.exe is not available on Windows PATH."
}

if (-not (Get-Command VBoxManage.exe -ErrorAction SilentlyContinue)) {
    throw "VBoxManage.exe is not available on Windows PATH."
}

$resolvedDistro = Get-WslDistroName -Distro $Distro

$bootstrapCommand = @(
    "sudo apt-get update"
    "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ansible python3 openssh-client git curl"
) -join "; "

& wsl.exe -d $resolvedDistro -- bash -lc $bootstrapCommand

Write-Host "WSL bootstrap completed for distro '$resolvedDistro'."
