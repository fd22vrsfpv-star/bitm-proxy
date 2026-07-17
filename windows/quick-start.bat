@echo off
:: Quick-start for development / portable use.
:: Requires: Python 3.10+, Node.js 18+ already on PATH.
:: Run from the repo root: windows\quick-start.bat

title BITM Proxy - Quick Start
cd /d "%~dp0.."

echo.
echo  BITM Proxy - Quick Start
echo  ========================
echo.

:: ── Check prerequisites ──
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    pause & exit /b 1
)

node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Install Node.js 18+ from https://nodejs.org
    pause & exit /b 1
)

:: ── Set up data directories ──
set DATA_DIR=%LOCALAPPDATA%\BitmProxy\data
set SCREENSHOTS_DIR=%LOCALAPPDATA%\BitmProxy\screenshots
set CERTS_DIR=%LOCALAPPDATA%\BitmProxy\certs
set PYTHONUNBUFFERED=1
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%SCREENSHOTS_DIR%" mkdir "%SCREENSHOTS_DIR%"

:: ── Python venv ──
if not exist "venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    python -m venv venv
)
echo Installing Python dependencies...
venv\Scripts\pip install -r requirements.txt --quiet 2>nul

:: ── Playwright browsers ──
if not exist "%LOCALAPPDATA%\ms-playwright" (
    echo Installing Playwright Chromium browser...
    venv\Scripts\python -m playwright install chromium
)

:: ── Build frontend if needed ──
if not exist "static\index.html" (
    echo Building frontend...
    cd frontend
    call npm install --no-audit --no-fund >nul 2>&1
    call npm run build
    cd ..
    if exist "frontend\dist" (
        if exist "static" rmdir /s /q static
        xcopy frontend\dist static\ /e /i /q
    )
)

echo.
echo  Ready!
echo  Main app:        http://localhost:8091
echo  Debug dashboard: http://localhost:8092
echo.

start "" "http://localhost:8091"
venv\Scripts\python -m backend.run
pause
