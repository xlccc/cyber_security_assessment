@echo off
setlocal enabledelayedexpansion
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxHalfOpenRetried" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried') do set TcpMaxHalfOpenRetried=%%a
    if "!TcpMaxHalfOpenRetried!" NEQ "0x190" (
        echo !TcpMaxHalfOpenRetried!
        exit /b 0
    ) else (
        exit /b 1
    )
)

endlocal