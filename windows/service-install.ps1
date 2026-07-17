<#
.SYNOPSIS
    Install BITM Proxy as a Windows service.
    Runs on boot, no console window, survives logoff.

.NOTES
    Run as Administrator:
    powershell -ExecutionPolicy Bypass -File windows\service-install.ps1
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\BitmProxy"
)

$ErrorActionPreference = "Stop"

$appDir = "$InstallDir\app"
$venvPython = "$appDir\venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Error "BITM Proxy not installed. Run install.ps1 first."
    exit 1
}

Write-Host ""
Write-Host "  BITM Proxy - Service Installer" -ForegroundColor Cyan
Write-Host ""

# Install pywin32 if needed
Write-Host "Checking pywin32..." -ForegroundColor Yellow
$hasWin32 = & $venvPython -c "import win32serviceutil; print('ok')" 2>&1
if ($hasWin32 -ne "ok") {
    Write-Host "Installing pywin32..." -ForegroundColor Yellow
    & "$appDir\venv\Scripts\pip.exe" install pywin32 --quiet
    & $venvPython -m pywin32_postinstall -install 2>&1 | Out-Null
    Write-Host "pywin32 installed." -ForegroundColor Green
}

# Set environment for the service
Write-Host "Setting service environment variables..." -ForegroundColor Yellow
[System.Environment]::SetEnvironmentVariable("DATA_DIR", "$InstallDir\data", "Machine")
[System.Environment]::SetEnvironmentVariable("SCREENSHOTS_DIR", "$InstallDir\screenshots", "Machine")
[System.Environment]::SetEnvironmentVariable("CERTS_DIR", "$InstallDir\certs", "Machine")
[System.Environment]::SetEnvironmentVariable("PYTHONUNBUFFERED", "1", "Machine")

# Install the service
Write-Host "Installing service..." -ForegroundColor Yellow
Push-Location $appDir
& $venvPython -m backend.service install
Pop-Location

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "  Service installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Service name:  BitmProxy"
    Write-Host "  Startup type:  Automatic"
    Write-Host "  Main app:      http://localhost:8091"
    Write-Host "  Debug:         http://localhost:8092"
    Write-Host "  Log file:      $InstallDir\data\service.log"
    Write-Host ""

    $start = Read-Host "Start service now? (Y/n)"
    if ($start -ne 'n') {
        Start-Service BitmProxy
        Write-Host "Service started." -ForegroundColor Green
        Start-Process "http://localhost:8091"
    }
} else {
    Write-Error "Service install failed. Check the output above."
}

Write-Host ""
Write-Host "  Management commands:" -ForegroundColor Gray
Write-Host "    Start:   Start-Service BitmProxy"
Write-Host "    Stop:    Stop-Service BitmProxy"
Write-Host "    Restart: Restart-Service BitmProxy"
Write-Host "    Status:  Get-Service BitmProxy"
Write-Host "    Remove:  windows\service-remove.ps1"
Write-Host ""
