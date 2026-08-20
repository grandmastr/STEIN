@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Upgrade.ps1" %*
exit /b %ERRORLEVEL%

