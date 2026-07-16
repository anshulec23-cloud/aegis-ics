@echo off
echo Starting Aegis ICS...

:: Set PYTHONPATH so modules in src/ can be resolved
set PYTHONPATH=%cd%

:: Check if virtual environment exists and activate it
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo No virtual environment found. Make sure you have installed the requirements.
)

:: Run the application
echo Launching the desktop dashboard...
python src\main.py

:: Pause if there's an error so the user can read the output
if %errorlevel% neq 0 (
    echo.
    echo The application exited with an error.
    pause
)
