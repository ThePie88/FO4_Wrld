@echo off
REM Copy build\dxgi.dll into both FO4 game directories (Steam A + FO4_b).
REM The DLL MUST live next to Fallout4.exe for the Windows loader to find it.
REM Also mirrors assets\compiled\*.fwn so the runtime loader can find them at
REM the expected relative path (self_dir\assets\compiled\*.fwn).

setlocal EnableExtensions

set "DLL=%~dp0build\dxgi.dll"
if not exist "%DLL%" (
    echo [deploy] ERROR: %DLL% not found. Run build.bat first.
    exit /b 1
)

set "STEAM_DIR=C:\Program Files (x86)\Steam\steamapps\common\Fallout 4"
set "FO4B_DIR=%~dp0..\FO4_b"
set "ASSETS_SRC=%~dp0assets\compiled"
set "SPAI_MANIFEST=%~dp0..\assets\weapon_nif_catalog.manifest"

echo [deploy] source DLL:      %DLL%
echo [deploy] source assets:   %ASSETS_SRC%
echo [deploy] SPAI manifest:   %SPAI_MANIFEST%
echo.

REM --- Side A: Steam install
echo [deploy] Side A: %STEAM_DIR%
if not exist "%STEAM_DIR%" (
    echo [deploy]   SKIP - directory not found
) else (
    copy /Y "%DLL%" "%STEAM_DIR%\dxgi.dll" >nul
    if errorlevel 1 (
        echo [deploy]   DLL  FAIL - check FO4 is not running ^(locked DLL^)
    ) else (
        echo [deploy]   DLL  OK
    )
    if exist "%ASSETS_SRC%" (
        if not exist "%STEAM_DIR%\assets\compiled" mkdir "%STEAM_DIR%\assets\compiled"
        xcopy /Y /Q /I "%ASSETS_SRC%\*.fwn" "%STEAM_DIR%\assets\compiled\" >nul
        if errorlevel 1 (
            echo [deploy]   FWN  FAIL
        ) else (
            echo [deploy]   FWN  OK
        )
    )
    if exist "%SPAI_MANIFEST%" (
        if not exist "%STEAM_DIR%\assets" mkdir "%STEAM_DIR%\assets"
        copy /Y "%SPAI_MANIFEST%" "%STEAM_DIR%\assets\weapon_nif_catalog.manifest" >nul
        if errorlevel 1 (
            echo [deploy]   SPAI FAIL
        ) else (
            echo [deploy]   SPAI OK
        )
    ) else (
        echo [deploy]   SPAI SKIP - manifest not found ^(run tools\spai_enum_weapons.py^)
    )
)

REM --- Side B: FO4_b
echo [deploy] Side B: %FO4B_DIR%
if not exist "%FO4B_DIR%" (
    echo [deploy]   SKIP - directory not found
) else (
    copy /Y "%DLL%" "%FO4B_DIR%\dxgi.dll" >nul
    if errorlevel 1 (
        echo [deploy]   DLL  FAIL - check FO4_b is not running
    ) else (
        echo [deploy]   DLL  OK
    )
    if exist "%ASSETS_SRC%" (
        if not exist "%FO4B_DIR%\assets\compiled" mkdir "%FO4B_DIR%\assets\compiled"
        xcopy /Y /Q /I "%ASSETS_SRC%\*.fwn" "%FO4B_DIR%\assets\compiled\" >nul
        if errorlevel 1 (
            echo [deploy]   FWN  FAIL
        ) else (
            echo [deploy]   FWN  OK
        )
    )
    if exist "%SPAI_MANIFEST%" (
        if not exist "%FO4B_DIR%\assets" mkdir "%FO4B_DIR%\assets"
        copy /Y "%SPAI_MANIFEST%" "%FO4B_DIR%\assets\weapon_nif_catalog.manifest" >nul
        if errorlevel 1 (
            echo [deploy]   SPAI FAIL
        ) else (
            echo [deploy]   SPAI OK
        )
    ) else (
        echo [deploy]   SPAI SKIP - manifest not found ^(run tools\spai_enum_weapons.py^)
    )
)

echo.
echo [deploy] Done. Launch FO4 via launcher\start_A.bat (or start_B.bat)
echo [deploy] and inspect fw_native.log in each game dir.

endlocal
