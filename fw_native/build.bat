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

REM 2026-09-18 — l'uscita si CANCELLA prima di ricostruire.
REM
REM Motivo: in un fallimento di link osservato oggi il bat ha stampato
REM "[build] OK" nonostante ninja avesse fermato la compilazione. Un OK
REM falso fa deployare la DLL VECCHIA, e da li' si insegue un fantasma:
REM si testa un binario che non contiene la modifica e si conclude che
REM la modifica non funziona. Cancellandola prima, una build fallita non
REM lascia niente da deployare e deploy.bat protesta invece di mentire.
if exist "build\dxgi.dll" del /q "build\dxgi.dll"

cmake --build --preset=msvc-release
if errorlevel 1 (
    echo [build] ERROR: cmake build failed
    exit /b 1
)

REM E si verifica che esista davvero, non che il comando sia tornato zero.
if not exist "build\dxgi.dll" (
    echo [build] ERROR: la compilazione non ha prodotto build\dxgi.dll
    echo [build]        NON deployare: la copia installata e' quella vecchia.
    exit /b 1
)

echo.
echo [build] OK: build\dxgi.dll
echo [build] Next: deploy.bat  ^&^&  launcher\start_A.bat
endlocal
