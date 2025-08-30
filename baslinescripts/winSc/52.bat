@echo off
setlocal enabledelayedexpansion

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoDisconnect" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoDisconnect"') do set AutoDisconnect=%%a
    if "!AutoDisconnect!" NEQ "0xf" (
        echo !AutoDisconnect!
        exit /b 0
    ) else (
        exit /b 1
    )
)

endlocal