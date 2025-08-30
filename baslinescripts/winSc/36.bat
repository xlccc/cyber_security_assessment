@echo off
setlocal enabledelayedexpansion
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxHalfOpen" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen') do set TcpMaxHalfOpen=%%a
    set TcpMaxHalfOpen=!TcpMaxHalfOpen: =!
    if "!TcpMaxHalfOpenQ!" NEQ "0x1f4" (
        echo !TcpMaxHalfOpenQ!
        exit /b 0
    ) else (
        exit /b 1
    )
)
endlocal