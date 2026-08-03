# 构建内置 bytecode-gen.jar（通用 touch/exec 字节码）
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$env:HTTP_PROXY = if ($env:HTTP_PROXY) { $env:HTTP_PROXY } else { "http://127.0.0.1:10808" }
$env:HTTPS_PROXY = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } else { $env:HTTP_PROXY }

Write-Host "[*] mvn package ..."
mvn -DskipTests package
if ($LASTEXITCODE -ne 0) { throw "mvn package failed" }

$Jar = Join-Path $Root "target\bytecode-gen.jar"
$DestDir = Join-Path $Root "..\..\src\fastjson_toolkit\poc\bytecode\jars"
New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item $Jar (Join-Path $DestDir "bytecode-gen.jar") -Force
Write-Host "[+] installed -> $DestDir\bytecode-gen.jar"
