@echo off
REM Launcher che apre 5 terminali — 1 server + sender/receiver per istanza A e B.
REM USO: passa i 2 PID come argomenti: launch_all.bat <PID_A> <PID_B>

if "%~2"=="" (
    echo Uso: launch_all.bat PID_A PID_B
    echo PID_A = Fallout4.exe dell'istanza Steam originale
    echo PID_B = Fallout4.exe dell'istanza FO4_b
    echo Ottieni i PID da Task Manager o con: tasklist /FI "IMAGENAME eq Fallout4.exe"
    exit /b 1
)

set PID_A=%~1
set PID_B=%~2
set NET=C:\Users\filip\Desktop\FalloutWorld\net

start "server"       cmd /k python %NET%\server.py
timeout /t 1 /nobreak >nul
start "sender A"     cmd /k python %NET%\sender.py --pid %PID_A% --id player_A
start "sender B"     cmd /k python %NET%\sender.py --pid %PID_B% --id player_B
timeout /t 1 /nobreak >nul
start "recv npc A"   cmd /k python %NET%\receiver_npc.py --pid %PID_A% --id recv_A
start "recv npc B"   cmd /k python %NET%\receiver_npc.py --pid %PID_B% --id recv_B

echo Tutti i processi avviati. Chiudi i terminali per fermarli.
