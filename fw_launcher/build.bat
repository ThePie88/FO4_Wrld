@echo off
REM fw_launcher build wrapper. Same pattern as fw_native: vcvars64 + cmake + ninja.

setlocal EnableExtensions

set "VCVARS=E:\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [build] ERROR: vcvars64.bat not found at %VCVARS%
    exit /b 1
)

call "%VCVARS%" >nul
if errorlevel 1 (
    echo [build] ERROR: vcvars64 failed
    exit /b 1
)

cd /d "%~dp0"

cmake --preset=msvc-release
if errorlevel 1 (
    echo [build] ERROR: cmake configure failed
    exit /b 1
)

cmake --build --preset=msvc-release
if errorlevel 1 (
    echo [build] ERROR: cmake build failed
    exit /b 1
)

echo.
echo [build] OK: build\FoM.exe
echo [build] Next: deploy.bat
endlocal
