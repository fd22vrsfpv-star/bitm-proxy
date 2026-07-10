<#
.SYNOPSIS
    Build a self-contained installer EXE using Inno Setup.
    Pre-builds the frontend and bundles everything into a single setup.exe.

.NOTES
    Prerequisites:
    - Node.js 18+ (for frontend build)
    - Python 3.10+ (for venv creation)
    - Inno Setup 6+ (iscc.exe on PATH, or installed to default location)

    Run from the repo root:
    powershell -ExecutionPolicy Bypass -File windows\build-installer.ps1
#>

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path "$RepoRoot\backend\main.py")) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

$BuildDir = "$RepoRoot\_build"
$AppDir = "$BuildDir\app"

Write-Host "Building MITM Proxy installer..." -ForegroundColor Cyan
Write-Host "Build dir: $BuildDir"

# Clean
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

# ── 1. Build frontend ─────────────────────────────────

Write-Host "Building frontend..." -ForegroundColor Yellow
Push-Location "$RepoRoot\frontend"
npm install --no-audit --no-fund 2>&1 | Out-Null
npm run build
Pop-Location
Copy-Item "$RepoRoot\frontend\dist" "$AppDir\static" -Recurse

# ── 2. Copy backend ───────────────────────────────────

Copy-Item "$RepoRoot\backend" "$AppDir\backend" -Recurse
Copy-Item "$RepoRoot\requirements.txt" "$AppDir\requirements.txt"

# ── 3. Create embedded Python venv ────────────────────

Write-Host "Creating Python venv..." -ForegroundColor Yellow
python -m venv "$AppDir\venv"
& "$AppDir\venv\Scripts\pip.exe" install --upgrade pip --quiet
& "$AppDir\venv\Scripts\pip.exe" install -r "$AppDir\requirements.txt" --quiet

Write-Host "Installing Playwright Chromium..." -ForegroundColor Yellow
& "$AppDir\venv\Scripts\python.exe" -m playwright install chromium

# ── 4. Create launcher ────────────────────────────────

$batContent = @'
@echo off
title MITM Proxy
cd /d "%~dp0app"

set DATA_DIR=%LOCALAPPDATA%\MitmProxy\data
set SCREENSHOTS_DIR=%LOCALAPPDATA%\MitmProxy\screenshots
set CERTS_DIR=%LOCALAPPDATA%\MitmProxy\certs
set PYTHONUNBUFFERED=1

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%SCREENSHOTS_DIR%" mkdir "%SCREENSHOTS_DIR%"
if not exist "%CERTS_DIR%" mkdir "%CERTS_DIR%"

echo.
echo  MITM Proxy
echo  ================================
echo  Main app:        http://localhost:8091
echo  Debug dashboard: http://localhost:8092
echo  ================================
echo.

start "" "http://localhost:8091"
"venv\Scripts\python.exe" -m backend.run
pause
'@
Set-Content -Path "$BuildDir\MitmProxy.bat" -Value $batContent -Encoding ASCII

# ── 5. Find Inno Setup compiler ───────────────────────

$iscc = $null
if (Get-Command "iscc" -ErrorAction SilentlyContinue) {
    $iscc = "iscc"
} elseif (Test-Path "C:\Program Files (x86)\Inno Setup 6\ISCC.exe") {
    $iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
} elseif (Test-Path "C:\Program Files\Inno Setup 6\ISCC.exe") {
    $iscc = "C:\Program Files\Inno Setup 6\ISCC.exe"
}

if ($iscc) {
    Write-Host "Compiling installer with Inno Setup..." -ForegroundColor Yellow
    & $iscc "$RepoRoot\windows\setup.iss" /DBuildDir="$BuildDir"
    Write-Host "Installer built!" -ForegroundColor Green
    Write-Host "Output: $BuildDir\Output\MitmProxySetup.exe"
} else {
    Write-Host ""
    Write-Host "Inno Setup not found - skipping .exe creation." -ForegroundColor Yellow
    Write-Host "Install from https://jrsoftware.org/isdl.php then re-run."
    Write-Host "Build artifacts are in: $BuildDir"
}
