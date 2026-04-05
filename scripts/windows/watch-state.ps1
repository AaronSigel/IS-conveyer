param(
    [string]$Distro = "Ubuntu",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

Invoke-WslScript -Distro $Distro -ScriptPath "./scripts/watch-state.sh" -Arguments $ScriptArgs
