@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan-and-report.ps1" %*
