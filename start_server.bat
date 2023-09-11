@echo off
setlocal enabledelayedexpansion

:: Activate virtual environment
echo Activating virtual environment...
call .\myenv\Scripts\activate

if errorlevel 1 (
    echo Error during virtual environment activation.
    exit /b 1
)

echo Virtual environment activated.

:: Start the server
echo Starting server...
python server.py

if errorlevel 1 (
    echo Error during server start-up.
    exit /b 1
)

endlocal
