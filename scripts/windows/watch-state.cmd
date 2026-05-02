@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch-state.ps1" %*
