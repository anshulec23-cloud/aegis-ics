@echo off
REM ============================================================
REM  Aegis ICS — Windows Launcher
REM  Double-click this file to start
REM ============================================================
title Aegis ICS Launcher
color 0A

echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║         AEGIS ICS — SERVICE LAUNCHER              ║
echo  ║   Zero-Trust ICS/OT Security Platform             ║
echo  ╚═══════════════════════════════════════════════════╝
echo.

REM Check for Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Setup virtual environment if needed
if not exist ".venv\Scripts\python.exe" (
    echo [+] Creating virtual environment...
    python -m venv .venv
)

REM Install dependencies
echo [+] Installing dependencies...
.venv\Scripts\pip install --quiet -r server\api\requirements.txt
.venv\Scripts\pip install --quiet -r version-two\requirements.txt

REM Generate .env if missing
if not exist ".env" (
    echo [+] Creating .env from template...
    copy .env.example .env >nul
)

echo.
echo  Select version to launch:
echo.
echo    [1] Version 1 (Zero-Trust OT, TLS, Trust Engine)
echo    [2] Version 2 (Stuxnet-Proof SCADA, SQL Auditing)
echo    [3] Run all tests
echo    [4] Exit
echo.

set /p choice="  Enter option [1-4]: "

if "%choice%"=="1" goto v1
if "%choice%"=="2" goto v2
if "%choice%"=="3" goto test
if "%choice%"=="4" exit /b 0
echo Invalid option.
pause
exit /b 1

:v1
echo [+] Starting Version 1...
start "Aegis V1 Server" cmd /k ".venv\Scripts\python.exe -m server.api.app"
timeout /t 1 /nobreak >nul
start "Aegis V1 Simulator" cmd /k ".venv\Scripts\python.exe esp32_sim\simulator.py --config esp32_sim\device_config.json"
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
echo [OK] Version 1 is running. Close the spawned windows to stop.
pause
exit /b 0

:v2
echo [+] Starting Version 2...
cd version-two
start "Aegis V2 SCADA" cmd /k "..\.venv\Scripts\python.exe app.py"
timeout /t 1 /nobreak >nul
start "Aegis V2 Simulator" cmd /k "..\.venv\Scripts\python.exe simulator.py"
cd ..
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
echo [OK] Version 2 is running. Login: admin / admin
pause
exit /b 0

:test
echo [+] Running test suites...
.venv\Scripts\python.exe -m unittest discover -s tests -v
echo.
.venv\Scripts\python.exe -m unittest discover -s version-two -v
echo.
echo [OK] All tests complete.
pause
exit /b 0
