@echo off
setlocal enabledelayedexpansion
for /f "tokens=3" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA"') do set EnableLUA=%%a
if "!EnableLUA!" NEQ "0x1" (
    exit /b 0
) else (
    exit /b 1
)
endlocal