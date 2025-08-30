@echo off
setlocal enabledelayedexpansion

reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun > result.txt 2>&1
if %errorlevel% NEQ 0 (
    echo null
    exit /b 1
) else (
    for /f "tokens=3" %%a in ('reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun') do set noDriveTypeAutoRun=%%a
    if "!noDriveTypeAutoRun!" NEQ "0xff" (
        echo !noDriveTypeAutoRun!
        exit /b 0
    ) else (
        exit /b 1
    )
)

endlocal