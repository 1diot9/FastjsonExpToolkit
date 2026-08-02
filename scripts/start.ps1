# Start FastjsonExpToolkit Web (backend + frontend). Windows PowerShell.
# Does NOT start/stop Docker lab.
# Backend: uvicorn --reload; Frontend: Next.js HMR.
param(
    [switch]$NoPause,
    [switch]$NoReload
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$Runtime = Join-Path $Root ".runtime"
$LogDir = Join-Path $Runtime "logs"
$PidBackend = Join-Path $Runtime "backend.pid"
$PidFrontend = Join-Path $Runtime "frontend.pid"
$BackendHost = if ($env:BACKEND_HOST) { $env:BACKEND_HOST } else { "127.0.0.1" }
$BackendPort = if ($env:BACKEND_PORT) { [int]$env:BACKEND_PORT } else { 8000 }
$FrontendPort = if ($env:FRONTEND_PORT) { [int]$env:FRONTEND_PORT } else { 3000 }
$EnableReload = -not $NoReload
if ($env:BACKEND_RELOAD -eq "0") { $EnableReload = $false }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Test-PidRunning([string]$PidFile) {
    if (-not (Test-Path $PidFile)) { return $false }
    $procId = Get-Content $PidFile -ErrorAction SilentlyContinue
    if (-not $procId) { return $false }
    try {
        Get-Process -Id ([int]$procId) -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        return $false
    }
}

function Test-PortInUse([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return $null -ne $conn
}

Write-Host "[*] project: $Root"

if ((Test-PidRunning $PidBackend) -or (Test-PortInUse $BackendPort)) {
    Write-Host "[!] backend already running (:$BackendPort)"
} else {
    $importOk = $false
    try {
        python -c "import fastjson_toolkit" 2>$null
        if ($LASTEXITCODE -eq 0) { $importOk = $true }
    } catch {}
    if (-not $importOk) {
        Write-Host "[*] installing Python package (editable)..."
        pip install -e $Root
    }

    $reloadHint = if ($EnableReload) { " (auto-reload)" } else { "" }
    Write-Host "[*] starting backend http://${BackendHost}:$BackendPort$reloadHint"
    $backendOut = Join-Path $LogDir "backend.out.log"
    $backendErr = Join-Path $LogDir "backend.err.log"
    $srcDir = Join-Path $Root "src"
    $args = @(
        "-m", "uvicorn", "fastjson_toolkit.api.app:app",
        "--host", $BackendHost,
        "--port", "$BackendPort"
    )
    if ($EnableReload) {
        $args += @(
            "--reload",
            "--reload-dir", $srcDir,
            "--reload-include", "*.py"
        )
    }
    $proc = Start-Process -FilePath "python" -ArgumentList $args `
        -WorkingDirectory $Root `
        -RedirectStandardOutput $backendOut `
        -RedirectStandardError $backendErr `
        -WindowStyle Hidden `
        -PassThru
    Set-Content -Path $PidBackend -Value $proc.Id -Encoding ascii

    # Wait until health endpoint is ready so the Web UI does not flash "API 未连接".
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $resp = Invoke-WebRequest -Uri "http://${BackendHost}:$BackendPort/api/health" -UseBasicParsing -TimeoutSec 1
            if ($resp.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
    }
    if ($ready) {
        Write-Host "[+] backend ready"
    } else {
        Write-Host "[!] backend started but health check timed out — see logs"
    }
}

if ((Test-PidRunning $PidFrontend) -or (Test-PortInUse $FrontendPort)) {
    Write-Host "[!] frontend already running (:$FrontendPort)"
} else {
    $nm = Join-Path $Root "web\node_modules"
    if (-not (Test-Path $nm)) {
        Write-Host "[*] npm install (web)..."
        Push-Location (Join-Path $Root "web")
        try { npm install } finally { Pop-Location }
    }

    Write-Host "[*] starting frontend http://127.0.0.1:$FrontendPort (HMR)"
    $frontendOut = Join-Path $LogDir "frontend.out.log"
    $frontendErr = Join-Path $LogDir "frontend.err.log"
    $webDir = Join-Path $Root "web"
    $npmCmd = if (Get-Command npm.cmd -ErrorAction SilentlyContinue) { "npm.cmd" } else { "npm" }
    $proc = Start-Process -FilePath $npmCmd -ArgumentList @(
        "run", "dev", "--", "--port", "$FrontendPort"
    ) -WorkingDirectory $webDir -RedirectStandardOutput $frontendOut -RedirectStandardError $frontendErr -WindowStyle Hidden -PassThru
    Set-Content -Path $PidFrontend -Value $proc.Id -Encoding ascii
}

Write-Host ""
Write-Host "[+] done"
Write-Host "    Web UI : http://127.0.0.1:$FrontendPort"
Write-Host "    API    : http://${BackendHost}:$BackendPort/api/health"
Write-Host "    Docs   : http://${BackendHost}:$BackendPort/api/docs"
Write-Host "    logs   : $LogDir"
Write-Host "    stop   : .\scripts\stop.ps1  or  .\scripts\stop.bat"
if ($EnableReload) {
    Write-Host "    reload : backend watches src/ ; frontend Next.js HMR"
}

if (-not $NoPause) {
    Write-Host ""
    Write-Host "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
