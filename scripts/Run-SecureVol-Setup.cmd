@echo off
setlocal
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Install-SecureVol-Admin.ps1" -EnableTestSigning -EnableProtection %*
endlocal
