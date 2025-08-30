@echo off
setlocal enabledelayedexpansion

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectResponseRetransmissions" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions') do set TcpMaxConnectResponseRetransmissions=%%a
    if "!TcpMaxConnectResponseRetransmissions!" NEQ "0x2" (
        echo !TcpMaxConnectResponseRetransmissions!
        exit /b 0
    ) else (
        exit /b 1
    )
)
endlocal