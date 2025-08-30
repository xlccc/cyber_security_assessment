@echo off
sc query "DHCPServer" > result.txt

if %errorlevel% neq 0 (
    echo null.
    del "result.txt" /q
    exit /b 1
) else (
    for /f "tokens=3" %%A in ('type result.txt ^| findstr /C:"STATE"') do (
        set dhcpServerStatus=%%A
    )
    if /i "%dhcpServerStatus%" NEQ "STOPPED" (
        del "result.txt" /q
        exit /b 0
    ) else (
        del "result.txt" /q
        exit /b 1
    )
)
