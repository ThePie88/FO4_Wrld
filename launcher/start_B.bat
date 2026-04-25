@echo off
REM FalloutWorld Launcher — Player B (ColdClient + FO4_b steamless)
REM Double-click to start. Leave this window open.
REM NOTE: Player A must be running FIRST (see the single-instance patch note).

title FalloutWorld - Player B

cd /d "%~dp0\.."
python -m launcher.main --side B --no-server

echo.
echo Launcher exited. Press any key to close.
pause >nul
