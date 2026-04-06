param(
    [string]$Distro = "Ubuntu",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

Ensure-VirtualBoxHostOnlyAdapter | Out-Null

if ($ScriptArgs.Count -gt 0) {
    Invoke-WindowsVagrant -Arguments (@("up") + $ScriptArgs)
}
else {
    foreach ($machine in @("wazuh", "target1", "target2")) {
        Invoke-WindowsVagrant -Arguments @("up", $machine)
    }
}
