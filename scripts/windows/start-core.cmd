@echo off
setlocal

rem Keep CORE presentation-independent and restart it after a non-zero exit.
rem Ten quick retries are followed by Task Scheduler's slower restart policy,
rem which prevents an unbounded tight loop if the binary is persistently bad.
set "STEIN_PROOF_MARKER=%~dp0..\data\supervision-proof.once"
set "STEIN_RETRIES=0"

:launch
"%~dp0stein-core.exe" --installed
set "STEIN_EXIT_CODE=%ERRORLEVEL%"

rem The smoke proof asks CORE to drain cleanly, then converts that one exit to
rem a synthetic failure. This exercises the exact restart loop without killing
rem the process or corrupting in-memory state during shutdown.
if exist "%STEIN_PROOF_MARKER%" (
  del /f /q "%STEIN_PROOF_MARKER%" >nul 2>&1
  set "STEIN_EXIT_CODE=73"
)

if "%STEIN_EXIT_CODE%"=="0" exit /b 0
set /a STEIN_RETRIES+=1
if %STEIN_RETRIES% GEQ 10 exit /b %STEIN_EXIT_CODE%
timeout.exe /t 2 /nobreak >nul
goto launch
