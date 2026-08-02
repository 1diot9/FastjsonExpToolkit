# Stop FastjsonExpToolkit Web (backend + frontend). Windows PowerShell.
# Does NOT stop Docker lab.
param(
    [switch]$NoPause
)

$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runtime = Join-Path $Root ".runtime"
$PidBackend = Join-Path $Runtime "backend.pid"
$PidFrontend = Join-Path $Runtime "frontend.pid"
$BackendPort = if ($env:BACKEND_PORT) { [int]$env:BACKEND_PORT } else { 8000 }
$FrontendPort = if ($env:FRONTEND_PORT) { [int]$env:FRONTEND_PORT } else { 3000 }

function Stop-PidFile([string]$Name, [string]$PidFile) {
    if (-not (Test-Path $PidFile)) { return }
    $procId = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($procId) {
        try {
            Get-Process -Id ([int]$procId) -ErrorAction Stop | Out-Null
            Write-Host "[*] stopping $Name (pid=$procId)"
            Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Stop-PortListeners([int]$Port) {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) { return }
    $ids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $ids) {
        if ($procId -and $procId -ne 0) {
            Write-Host "[*] freeing port :$Port (pid=$procId)"
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
}

Stop-PidFile "frontend" $PidFrontend
Stop-PidFile "backend" $PidBackend
Stop-PortListeners $FrontendPort
Stop-PortListeners $BackendPort

Write-Host "[+] stopped (Docker lab untouched)"

if (-not $NoPause) {
    Write-Host ""
    Write-Host "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
