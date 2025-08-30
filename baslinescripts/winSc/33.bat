setlocal enabledelayedexpansion
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxPortsExhausted" >nul 2>&1
if %errorlevel% neq 0 (
    echo null
    echo null
    exit /b 0
)else (
    for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxPortsExhausted"') do set TcpMaxPortsExhausted=%%a
    if "!TcpMaxPortsExhausted!" NEQ "0x5" (
        echo !TcpMaxPortsExhausted!
        exit /b 0
    ) else (
        exit /b 1
    )
)

endlocal