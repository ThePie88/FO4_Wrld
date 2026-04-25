@echo off
REM fw_native build wrapper. Sources MSVC vcvars64 from E:\BuildTools,
REM then runs cmake configure + build via the Ninja-backed preset.
REM
REM Re-run is safe: CMake is incremental, Ninja only rebuilds changed TUs.

setlocal EnableExtensions

set "VCVARS=E:\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [build] ERROR: vcvars64.bat not found at %VCVARS%
    echo [build]         Adjust build.bat if your toolchain lives elsewhere.
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
echo [build] OK: build\dxgi.dll
echo [build] Next: deploy.bat  ^&^&  launcher\start_A.bat
endlocal
