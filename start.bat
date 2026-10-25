@echo off
title SCADA Intrusion Detection & Quantum Security System
echo =========================================================================
echo   SCADA Intrusion Detection ^& BB84 Quantum Security System
echo =========================================================================
echo.

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe!
    echo Please create the virtual environment first:
    echo    python -m venv .venv
    echo    .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo [*] Initializing SCADA Security System...
echo [*] Web Dashboard will be available at: http://127.0.0.1:5000/
echo [*] Modbus TCP Server listening on:     127.0.0.1:5020
echo.

:: Automatically open browser in background after 2 seconds
start "" /b cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:5000/"

:: Start main system
".venv\Scripts\python.exe" main.py

echo.
echo [*] SCADA System stopped.
pause
