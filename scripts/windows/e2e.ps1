param(
    [string]$Distro = "Ubuntu",
    [switch]$SkipSmokeTest,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

$arguments = New-Object System.Collections.Generic.List[string]

if ($SkipSmokeTest) {
    $arguments.Add("--skip-smoke-test")
}

foreach ($arg in $ScriptArgs) {
    $arguments.Add($arg)
}

Invoke-WslScript -Distro $Distro -ScriptPath "./scripts/e2e.sh" -Arguments $arguments
