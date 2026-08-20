@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Status.ps1" %*
exit /b %ERRORLEVEL%

