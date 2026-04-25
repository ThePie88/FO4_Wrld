@echo off
REM Deploy FoM.exe to the repo root so the user can double-click it directly.
REM We ship one exe — the side is chosen at runtime (argv --side or prompt).

setlocal EnableExtensions
cd /d "%~dp0"

set "SRC=build\FoM.exe"
if not exist "%SRC%" (
    echo [deploy] ERROR: %SRC% not found. Run build.bat first.
    exit /b 1
)

echo [deploy] source: %cd%\%SRC%

REM repo root is the parent of fw_launcher\
set "DST=..\FoM.exe"
copy /Y "%SRC%" "%DST%" >nul
if errorlevel 1 (
    echo [deploy] ERROR: copy to %DST% failed
    exit /b 1
)
echo [deploy]   OK -^> %DST%

echo.
echo [deploy] Done. Double-click FoM.exe in the repo root, or:
echo [deploy]   FoM.exe --side A
echo [deploy]   FoM.exe --side B
endlocal
