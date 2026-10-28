@echo off
REM Lance l audit en local avec elevation UAC (double-clic). Les arguments sont transmis au script.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Elevation requise...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-PreUpgradeAudit.ps1" %*
echo.
pause
