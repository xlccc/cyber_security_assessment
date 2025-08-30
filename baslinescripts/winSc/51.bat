@echo off
setlocal enabledelayedexpansion

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer') do set autoShareServer=%%a
    if "!autoShareServer!" NEQ "0x0" (
        exit /b 0
    ) else (
        exit /b 1
    )
)
endlocal