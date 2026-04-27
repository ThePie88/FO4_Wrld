@echo off
REM Attach TTD recorder to running Fallout4.exe.
REM Run as Administrator. Optional arg: PID to attach to.

setlocal EnableDelayedExpansion

REM Use script-relative paths (works from any clone location).
set "TTD_DIR=%~dp0ttd_local"
set "OUT_DIR=%~dp0ttd_traces"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM List all Fallout4.exe PIDs
echo.
echo [ttd] Fallout4.exe instances:
tasklist /FI "IMAGENAME eq Fallout4.exe"
echo.

REM Use PID from arg, else first found
set "FO4_PID=%~1"
if "%FO4_PID%"=="" (
    for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq Fallout4.exe" /NH') do (
        if not defined FO4_PID set "FO4_PID=%%i"
    )
)

if "%FO4_PID%"=="" (
    echo [ttd] ERRORE: Fallout4.exe non in esecuzione.
    pause
    exit /b 1
)

echo ========================================================
echo  TTD attach -^> Fallout4.exe PID=%FO4_PID%
echo  Output:  %OUT_DIR%\fo4_skin.run
echo  Per attaccarsi all'altra istanza, rilancia con:
echo     ttd_attach.bat ALTRO_PID
echo ========================================================
echo.
echo  STEPS:
echo    1. Premi un tasto, parte il recording
echo    2. Torna sul gioco, vai 3rd person, avvicinati al body
echo    3. Lascia girare 10 secondi (bone-test cycle gia' attivo)
echo    4. Torna qui, premi Ctrl+C per fermare
echo.
pause

"%TTD_DIR%\TTD.exe" -accepteula -attach %FO4_PID% -out "%OUT_DIR%\fo4_skin.run"

echo.
echo [ttd] Recording terminato. File: %OUT_DIR%\fo4_skin.run
echo [ttd] Torna a Claude e scrivi "fatto"
pause
