@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0check-boundaries.ps1" %*
exit /b %ERRORLEVEL%
