@echo off
setlocal enabledelayedexpansion

:: Check for Python installation
echo Checking if Python is installed...
python --version > NUL 2>&1

if errorlevel 1 (
    echo Python not found. Installing...
    python.exe /quiet InstallAllUsers=1 PrependPath=1
    if errorlevel 1 (
        echo Error during Python installation.
        exit /b 1
    )
    echo Python installed.
) else (
    echo Python is already installed.
)

:: Set up virtual environment
echo Setting up virtual environment...
python -m venv myenv

if errorlevel 1 (
    echo Error during virtual environment setup.
    exit /b 1
)

echo Virtual environment setup complete.

:: Activate virtual environment and install requirements
echo Activating virtual environment...
call .\myenv\Scripts\activate

echo Installing requirements...
pip install -r requirements.txt

if errorlevel 1 (
    echo Error during requirements installation.
    exit /b 1
)

echo Requirements installed.

endlocal
