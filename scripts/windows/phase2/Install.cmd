@echo off
setlocal
set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 set "STEIN_WINDOWS_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%STEIN_WINDOWS_POWERSHELL%" goto :host_unavailable
for %%I in ("%STEIN_WINDOWS_POWERSHELL%") do set "STEIN_WINDOWS_POWERSHELL_ATTRIBUTES=%%~aI"
for %%I in ("%STEIN_WINDOWS_POWERSHELL%") do set "STEIN_WINDOWS_POWERSHELL_SIZE=%%~zI"
if not defined STEIN_WINDOWS_POWERSHELL_ATTRIBUTES goto :host_unavailable
if not defined STEIN_WINDOWS_POWERSHELL_SIZE goto :host_unavailable
if /i "%STEIN_WINDOWS_POWERSHELL_ATTRIBUTES:~0,1%"=="d" goto :host_unavailable
if not "%STEIN_WINDOWS_POWERSHELL_ATTRIBUTES:l=%"=="%STEIN_WINDOWS_POWERSHELL_ATTRIBUTES%" goto :host_unavailable
if "%STEIN_WINDOWS_POWERSHELL_SIZE%"=="0" goto :host_unavailable
"%STEIN_WINDOWS_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %*
exit /b %ERRORLEVEL%
:host_unavailable
>&2 echo Required Windows PowerShell host is unavailable.
exit /b 1
