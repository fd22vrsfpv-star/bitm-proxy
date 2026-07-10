#Requires -RunAsAdministrator
<#
.SYNOPSIS
    MITM Proxy - Windows standalone installer.
    Installs Python, Node.js (if missing), builds the frontend, installs
    Python dependencies + Playwright browsers, and creates a Start Menu shortcut.

.NOTES
    Run from the repo root:  powershell -ExecutionPolicy Bypass -File windows\install.ps1
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\MitmProxy",
    [switch]$SkipPython,
    [switch]$SkipNode,
    [switch]$NoBrowser   # don't open the browser after install
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path "$RepoRoot\backend\main.py")) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
if (-not (Test-Path "$RepoRoot\backend\main.py")) {
    Write-Error "Cannot find backend\main.py - run this script from the repo root or windows\ directory."
    exit 1
}

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  MITM Proxy - Windows Installer"     -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repo root  : $RepoRoot"
Write-Host "Install dir: $InstallDir"
Write-Host ""

# ── Helpers ──────────────────────────────────────────────

function Test-Command($cmd) {
    try { Get-Command $cmd -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

function Install-WinGet-Package($id, $name) {
    Write-Host "Installing $name via winget..." -ForegroundColor Yellow
    winget install --id $id --accept-source-agreements --accept-package-agreements -e
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# ── 1. Check / install Python ────────────────────────────

if (-not $SkipPython) {
    if (-not (Test-Command "python")) {
        Write-Host "Python not found. Installing..." -ForegroundColor Yellow
        if (Test-Command "winget") {
            Install-WinGet-Package "Python.Python.3.12" "Python 3.12"
        } else {
            Write-Error "Python is not installed and winget is not available. Please install Python 3.10+ from https://python.org and re-run."
            exit 1
        }
    }
    $pyVer = python --version 2>&1
    Write-Host "Python: $pyVer" -ForegroundColor Green
}

# ── 2. Check / install Node.js ───────────────────────────

if (-not $SkipNode) {
    if (-not (Test-Command "node")) {
        Write-Host "Node.js not found. Installing..." -ForegroundColor Yellow
        if (Test-Command "winget") {
            Install-WinGet-Package "OpenJS.NodeJS.LTS" "Node.js LTS"
        } else {
            Write-Error "Node.js is not installed and winget is not available. Please install Node.js 18+ from https://nodejs.org and re-run."
            exit 1
        }
    }
    $nodeVer = node --version 2>&1
    Write-Host "Node.js: $nodeVer" -ForegroundColor Green
}

# ── 3. Create install directories ────────────────────────

$dirs = @(
    $InstallDir,
    "$InstallDir\data",
    "$InstallDir\screenshots",
    "$InstallDir\certs",
    "$InstallDir\app"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ── 4. Copy application files ────────────────────────────

Write-Host ""
Write-Host "Copying application files..." -ForegroundColor Yellow

$appDir = "$InstallDir\app"

# Copy backend
if (Test-Path "$appDir\backend") { Remove-Item "$appDir\backend" -Recurse -Force }
Copy-Item "$RepoRoot\backend" "$appDir\backend" -Recurse
Copy-Item "$RepoRoot\requirements.txt" "$appDir\requirements.txt" -Force

# Copy frontend source for building
$frontendBuildDir = "$appDir\_frontend_build"
if (Test-Path $frontendBuildDir) { Remove-Item $frontendBuildDir -Recurse -Force }
Copy-Item "$RepoRoot\frontend" $frontendBuildDir -Recurse

# Copy certs if any
if (Test-Path "$RepoRoot\certs") {
    Copy-Item "$RepoRoot\certs\*" "$InstallDir\certs\" -Force -ErrorAction SilentlyContinue
}

# ── 5. Python virtual environment + dependencies ─────────

Write-Host ""
Write-Host "Setting up Python virtual environment..." -ForegroundColor Yellow

$venvDir = "$appDir\venv"
if (-not (Test-Path "$venvDir\Scripts\python.exe")) {
    python -m venv $venvDir
}

$pip = "$venvDir\Scripts\pip.exe"
$python = "$venvDir\Scripts\python.exe"

& $pip install --upgrade pip --quiet
& $pip install -r "$appDir\requirements.txt" --quiet
Write-Host "Python dependencies installed." -ForegroundColor Green

# ── 6. Install Playwright browsers ───────────────────────

Write-Host ""
Write-Host "Installing Playwright browsers (Chromium)..." -ForegroundColor Yellow
& $python -m playwright install chromium
Write-Host "Playwright browsers installed." -ForegroundColor Green

# ── 7. Build frontend ────────────────────────────────────

Write-Host ""
Write-Host "Building frontend..." -ForegroundColor Yellow

Push-Location $frontendBuildDir
try {
    npm install --no-audit --no-fund 2>&1 | Out-Null
    npm run build 2>&1

    $distDir = "$frontendBuildDir\dist"
    $staticDir = "$appDir\static"
    if (Test-Path $staticDir) { Remove-Item $staticDir -Recurse -Force }
    Copy-Item $distDir $staticDir -Recurse
    Write-Host "Frontend built successfully." -ForegroundColor Green
} finally {
    Pop-Location
}

# Clean up frontend build artifacts
Remove-Item $frontendBuildDir -Recurse -Force -ErrorAction SilentlyContinue

# ── 8. Create launcher scripts ───────────────────────────

Write-Host ""
Write-Host "Creating launcher scripts..." -ForegroundColor Yellow

# Batch launcher
$batContent = @"
@echo off
title MITM Proxy
cd /d "$appDir"

set DATA_DIR=$InstallDir\data
set SCREENSHOTS_DIR=$InstallDir\screenshots
set CERTS_DIR=$InstallDir\certs
set PYTHONUNBUFFERED=1

echo.
echo  MITM Proxy
echo  ================================
echo  Main app:        http://localhost:8091
echo  Debug dashboard: http://localhost:8092
echo  Data dir:        %DATA_DIR%
echo  ================================
echo.

start "" "http://localhost:8091"
"$venvDir\Scripts\python.exe" -m backend.run
pause
"@
Set-Content -Path "$InstallDir\MitmProxy.bat" -Value $batContent -Encoding ASCII

# PowerShell launcher (alternative)
$ps1Content = @"
`$env:DATA_DIR = "$InstallDir\data"
`$env:SCREENSHOTS_DIR = "$InstallDir\screenshots"
`$env:CERTS_DIR = "$InstallDir\certs"
`$env:PYTHONUNBUFFERED = "1"

Set-Location "$appDir"

Write-Host ""
Write-Host "  MITM Proxy" -ForegroundColor Cyan
Write-Host "  Main app:        http://localhost:8091"
Write-Host "  Debug dashboard: http://localhost:8092"
Write-Host "  Data dir:        `$env:DATA_DIR"
Write-Host ""

Start-Process "http://localhost:8091"
& "$venvDir\Scripts\python.exe" -m backend.run
"@
Set-Content -Path "$InstallDir\MitmProxy.ps1" -Value $ps1Content -Encoding UTF8

# ── 9. Create Start Menu shortcut ────────────────────────

Write-Host "Creating Start Menu shortcut..." -ForegroundColor Yellow

$startMenu = [System.Environment]::GetFolderPath("Programs")
$shortcutPath = "$startMenu\MITM Proxy.lnk"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "$InstallDir\MitmProxy.bat"
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = "MITM Proxy - Remote browser login and API testing"
$shortcut.Save()

# Also create a Desktop shortcut
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$deskShortcut = $shell.CreateShortcut("$desktopPath\MITM Proxy.lnk")
$deskShortcut.TargetPath = "$InstallDir\MitmProxy.bat"
$deskShortcut.WorkingDirectory = $InstallDir
$deskShortcut.Description = "MITM Proxy - Remote browser login and API testing"
$deskShortcut.Save()

Write-Host "Shortcuts created." -ForegroundColor Green

# ── 10. Create uninstaller ────────────────────────────────

$uninstallContent = @"
# MITM Proxy Uninstaller
`$installDir = "$InstallDir"
`$confirm = Read-Host "Remove MITM Proxy from '`$installDir'? (y/N)"
if (`$confirm -eq 'y') {
    Remove-Item "`$installDir" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$startMenu\MITM Proxy.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item "$desktopPath\MITM Proxy.lnk" -Force -ErrorAction SilentlyContinue
    Write-Host "MITM Proxy removed." -ForegroundColor Green
} else {
    Write-Host "Cancelled."
}
"@
Set-Content -Path "$InstallDir\uninstall.ps1" -Value $uninstallContent -Encoding UTF8

# ── Done ──────────────────────────────────────────────────

Write-Host ""
Write-Host "====================================" -ForegroundColor Green
Write-Host "  Installation complete!"             -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install location: $InstallDir"
Write-Host "  Data directory:   $InstallDir\data"
Write-Host ""
Write-Host "  To start:  double-click 'MITM Proxy' on Desktop"
Write-Host "             or run: $InstallDir\MitmProxy.bat"
Write-Host ""
Write-Host "  Main app:        http://localhost:8091"
Write-Host "  Debug dashboard: http://localhost:8092"
Write-Host ""
Write-Host "  To uninstall:  powershell $InstallDir\uninstall.ps1"
Write-Host ""

if (-not $NoBrowser) {
    $run = Read-Host "Start MITM Proxy now? (Y/n)"
    if ($run -ne 'n') {
        Start-Process "$InstallDir\MitmProxy.bat"
    }
}
