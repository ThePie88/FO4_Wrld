@echo off
REM FalloutWorld Launcher — Player A (Steam + F4SE)
REM Double-click to start. Leave this window open.

title FalloutWorld - Player A

cd /d "%~dp0\.."
python -m launcher.main --side A

echo.
echo Launcher exited. Press any key to close.
pause >nul
