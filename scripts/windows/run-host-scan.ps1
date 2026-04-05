param(
    [string]$Distro = "Ubuntu",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

$arguments = New-Object System.Collections.Generic.List[string]
$arguments.Add("scripts/run-host-scan.py")
foreach ($arg in $ScriptArgs) {
    $arguments.Add($arg)
}

Invoke-WslScript -Distro $Distro -ScriptPath "python3" -Arguments $arguments
