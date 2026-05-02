@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-report.ps1" %*
