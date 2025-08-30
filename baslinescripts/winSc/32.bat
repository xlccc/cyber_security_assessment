@echo off
setlocal enabledelayedexpansion

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" >nul 2>&1
if %errorlevel% neq 0 (
    :: 如果项不存在，则不通过
    echo null
    exit /b 0
) else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting"') do (
        set DisableIPSourceRouting=%%a
    )
    if "!DisableIPSourceRouting!" NEQ "0x1" (
        echo "!DisableIPSourceRouting!"
        exit /b 0
    ) else (
        exit /b 1
    )
)

endlocal
