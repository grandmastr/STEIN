@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Verify-Source.ps1" %*
exit /b %ERRORLEVEL%
