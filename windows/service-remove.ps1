<#
.SYNOPSIS
    Remove the BITM Proxy Windows service.

.NOTES
    Run as Administrator:
    powershell -ExecutionPolicy Bypass -File windows\service-remove.ps1
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\BitmProxy"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  BITM Proxy - Service Removal" -ForegroundColor Cyan
Write-Host ""

# Stop service if running
$svc = Get-Service -Name "BitmProxy" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Write-Host "Stopping service..." -ForegroundColor Yellow
        Stop-Service BitmProxy -Force
        Start-Sleep -Seconds 2
    }

    $appDir = "$InstallDir\app"
    $venvPython = "$appDir\venv\Scripts\python.exe"

    if (Test-Path $venvPython) {
        Push-Location $appDir
        & $venvPython -m backend.service remove
        Pop-Location
    } else {
        # Fallback: use sc.exe
        sc.exe delete BitmProxy
    }

    Write-Host "Service removed." -ForegroundColor Green
} else {
    Write-Host "Service 'BitmProxy' not found." -ForegroundColor Yellow
}

# Clean up machine-level env vars
[System.Environment]::SetEnvironmentVariable("DATA_DIR", $null, "Machine")
[System.Environment]::SetEnvironmentVariable("SCREENSHOTS_DIR", $null, "Machine")
[System.Environment]::SetEnvironmentVariable("CERTS_DIR", $null, "Machine")

Write-Host "Done." -ForegroundColor Green
