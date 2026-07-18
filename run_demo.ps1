<#
.SYNOPSIS
  Run the DEF CON RTV lab (bitm-proxy + nginx) via docker-compose.
  See docs/DEFCON-LAB-SETUP.md for the full runbook.

.DESCRIPTION
  No login gate -- anyone who reaches the URL can use the lab. Safety comes
  from the proxy_allowed_hosts / phantom_join_allowed_domains allowlists
  (populate these before using -Public), not authentication.

  Quick start (safe default -- loopback only, self-signed cert):
    .\run_demo.ps1

.PARAMETER Public
  Bind on 0.0.0.0 instead of loopback-only. Only use this on a host you
  intend to be publicly reachable, with a real domain pointed at it and a
  real cert mounted (see the runbook) -- this is the organizer/public-
  instance flag, not the default self-hosted path.

.PARAMETER Rebuild
  Force a fresh image build (docker compose up --build).

.PARAMETER Logs
  Tail logs from both containers after starting.

.PARAMETER Stop
  Stop and remove the stack (docker compose down).

.EXAMPLE
  .\run_demo.ps1
.EXAMPLE
  .\run_demo.ps1 -Rebuild -Logs
.EXAMPLE
  .\run_demo.ps1 -Stop
#>
param(
    [switch]$Public,
    [switch]$Rebuild,
    [switch]$Logs,
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Test-DockerAvailable {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Host "x docker not found on PATH. Install Docker Desktop (WSL2 backend" -ForegroundColor Red
        Write-Host "  recommended), then re-run this script." -ForegroundColor Red
        exit 1
    }
    try {
        docker info | Out-Null
    } catch {
        Write-Host "x Docker is installed but not running. Start Docker Desktop," -ForegroundColor Red
        Write-Host "  then re-run this script." -ForegroundColor Red
        exit 1
    }
}

Test-DockerAvailable

if ($Stop) {
    Write-Host "==> Stopping the lab stack"
    docker compose down
    exit 0
}

if ($Public) {
    Write-Host "!  -Public: binding on 0.0.0.0. Only do this on a host you intend" -ForegroundColor Yellow
    Write-Host "   to be publicly reachable -- see docs/DEFCON-LAB-SETUP.md before" -ForegroundColor Yellow
    Write-Host "   using this for anything other than the organizer-run instance." -ForegroundColor Yellow
    Write-Host "!  There is no login gate on this stack -- anyone who reaches the URL" -ForegroundColor Yellow
    Write-Host "   can use it. Safety comes entirely from proxy_allowed_hosts /" -ForegroundColor Yellow
    Write-Host "   phantom_join_allowed_domains being populated before you expose this." -ForegroundColor Yellow
    $env:BIND_HOST = "0.0.0.0"
}

$buildArgs = @()
if ($Rebuild) { $buildArgs += "--build" }

# ── Dashboard JS syntax check (best-effort) ──────────────────────────────────
# The whole :8092 dashboard is one inline <script> in
# backend/debug_server.py; a single syntax error there silently kills it --
# the page still 200s but nothing runs and the WebSockets never connect.
# We check it before building the image. This needs Python + node on the
# host, which the Docker-only path doesn't otherwise require, so it's
# best-effort: skipped (with a note) when they aren't present, since a
# pure lab operator isn't editing the code -- only a developer who has
# them would hit (or need to catch) this.
if ($Rebuild) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($py -and $node) {
        Write-Host "==> Checking dashboard JS"
        & $py.Source (Join-Path $PSScriptRoot "scripts\check_dashboard_js.py")
        if ($LASTEXITCODE -ne 0) {
            Write-Error "dashboard JS check failed -- fix backend/debug_server.py before building."
            exit 1
        }
    } else {
        Write-Host "==> Skipping dashboard JS check (needs python + node on PATH)"
    }
}

# Base images default to UTC. Unlike run_demo.sh's macOS/Linux path, there's
# no reliable Windows-timezone-ID -> IANA-name conversion available in
# Windows PowerShell 5.1 (no .NET Core ICU APIs here), so this isn't
# auto-detected -- set $env:TZ yourself (e.g. "America/New_York") before
# running this script if you want container log timestamps to match your
# local clock instead of UTC.
if ($env:TZ) { Write-Host "==> Container time zone: $($env:TZ)" }

Write-Host "==> Starting the lab stack (this can take a while the first time --"
Write-Host "    building the app image, installing Playwright's Chromium, etc.)"
docker compose up @buildArgs -d

$hostAddr = if ($env:BIND_HOST) { $env:BIND_HOST } else { "127.0.0.1" }
Write-Host "==> Waiting for nginx to become reachable at https://$hostAddr/ ..."

# TCP-level check (not Invoke-WebRequest) so this works the same on both
# Windows PowerShell 5.1 and PowerShell 7+ without depending on
# -SkipCertificateCheck (a PS7-only Invoke-WebRequest parameter) to get
# past the self-signed cert.
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    $test = Test-NetConnection -ComputerName $hostAddr -Port 443 -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        $ready = $true
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $ready) {
    Write-Host "!  Didn't see a response yet -- it may still be starting. Check with:" -ForegroundColor Yellow
    Write-Host "     docker compose logs -f"
} else {
    Write-Host "OK Lab is up: https://$hostAddr/" -ForegroundColor Green
}

Write-Host ""
Write-Host "Open https://$hostAddr/ in your browser (click through the self-signed"
Write-Host "cert warning if you didn't mount a real one -- expected for local use)."

if ($ready) {
    try { Start-Process "https://$hostAddr/" } catch {}
}

if ($Logs) {
    Write-Host ""
    Write-Host "==> Tailing logs (Ctrl-C to stop tailing -- the stack keeps running)"
    docker compose logs -f
}
