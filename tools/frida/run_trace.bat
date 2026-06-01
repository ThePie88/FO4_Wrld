@echo off
REM ============================================================================
REM Combat AI Brain Frida Trace Launcher
REM ----------------------------------------------------------------------------
REM Attaches to the Fallout4.exe process (running) and runs combat_brain_trace.js.
REM
REM Output goes to a timestamped file in the same directory.
REM
REM Prerequisites:
REM   pip install frida-tools
REM   (Frida 16.x or later)
REM
REM Usage:
REM   1. Start Fallout4.exe normally (via launcher\start_A.bat or start_B.bat).
REM   2. Once in-game (main menu OK, save loaded), run this script.
REM   3. Do your test scenario (teleport, combat, etc.).
REM   4. When done or after crash, Ctrl-C and look at trace_*.log.
REM ============================================================================

setlocal EnableExtensions

REM Find the trace script directory.
set "SCRIPT_DIR=%~dp0"
set "SCRIPT=%SCRIPT_DIR%combat_brain_trace.js"

if not exist "%SCRIPT%" (
    echo [run] ERROR: %SCRIPT% not found.
    exit /b 1
)

REM Find Fallout4.exe by name. Frida will auto-attach by name.
set "TARGET=Fallout4.exe"

REM Build timestamp for log filename (PowerShell — wmic is deprecated on Win11).
for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "Get-Date -Format 'yyyyMMdd_HHmmss'"`) do set "TS=%%a"
if "%TS%"=="" set "TS=notime"
set "LOG=%SCRIPT_DIR%trace_%TS%.log"

REM Sanity: cleanup malformed historical filename from the wmic bug.
if exist "%SCRIPT_DIR%trace_~0,8DT" del "%SCRIPT_DIR%trace_~0,8DT"

REM Check that Fallout4.exe is actually running — Frida exits silently
REM with -o if the target is missing, leaving a 0-byte log.
tasklist /FI "IMAGENAME eq Fallout4.exe" /NH 2>nul | find /I "Fallout4.exe" >nul
if errorlevel 1 (
    echo [run] ERROR: Fallout4.exe is NOT running. Start the game first.
    exit /b 2
)

echo [run] Frida script: %SCRIPT%
echo [run] target:       %TARGET%
echo [run] output log:   %LOG%
echo.
echo [run] Attaching... (Ctrl-C to stop)
echo.

REM frida -n <name> attaches to running process by name.
REM --runtime=v8 is the default; included for clarity.
REM -l loads the script.
frida -n "%TARGET%" -l "%SCRIPT%" --runtime=v8 -o "%LOG%"

echo.
echo [run] Trace finished. Log: %LOG%
endlocal
