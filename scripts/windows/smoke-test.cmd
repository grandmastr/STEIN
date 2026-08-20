@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0smoke-test.ps1" %*
exit /b %ERRORLEVEL%
