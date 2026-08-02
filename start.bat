@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" -NoPause %*
echo.
pause
exit /b %ERRORLEVEL%
