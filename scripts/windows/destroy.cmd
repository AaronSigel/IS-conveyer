@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0destroy.ps1" %*
