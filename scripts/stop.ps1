# Stop FastjsonExpToolkit Web (backend + frontend). Windows PowerShell.
# Does NOT stop Docker lab.
param(
    [switch]$NoPause
)

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$Runtime = Join-Path $Root ".runtime"
$PidBackend = Join-Path $Runtime "backend.pid"
$PidFrontend = Join-Path $Runtime "frontend.pid"
$PortsFile = Join-Path $Runtime "ports.env"

# Prefer explicit env, then last start ports, then defaults.
$BackendPort = 8000
$FrontendPort = 3000
if (Test-Path $PortsFile) {
    Get-Content $PortsFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) { return }
        switch ($parts[0]) {
            "BACKEND_PORT" { $BackendPort = [int]$parts[1] }
            "FRONTEND_PORT" { $FrontendPort = [int]$parts[1] }
        }
    }
}
if ($env:BACKEND_PORT) { $BackendPort = [int]$env:BACKEND_PORT }
if ($env:FRONTEND_PORT) { $FrontendPort = [int]$env:FRONTEND_PORT }

function Stop-PidTree([int]$ProcId) {
    # Kill children first (uvicorn --reload spawns a worker).
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcId" -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-PidTree ([int]$_.ProcessId) }
    try {
        Stop-Process -Id $ProcId -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Stop-PidFile([string]$Name, [string]$PidFile) {
    if (-not (Test-Path $PidFile)) { return }
    $procId = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($procId) {
        try {
            Get-Process -Id ([int]$procId) -ErrorAction Stop | Out-Null
            Write-Host "[*] stopping $Name (pid=$procId)"
            Stop-PidTree ([int]$procId)
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
            Stop-PidTree ([int]$procId)
        }
    }
}

Stop-PidFile "frontend" $PidFrontend
Stop-PidFile "backend" $PidBackend
# Only free ports we recorded on start — avoid killing unrelated apps on :8000/:3000.
if (Test-Path $PortsFile) {
    Stop-PortListeners $FrontendPort
    Stop-PortListeners $BackendPort
    Remove-Item $PortsFile -Force -ErrorAction SilentlyContinue
}

Write-Host "[+] stopped (Docker lab untouched)"

if (-not $NoPause) {
    Write-Host ""
    Write-Host "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
