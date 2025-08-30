@echo off
sc query "DHCP" | find "STATE" > result.txt

for /f "tokens=4" %%A in ('type result.txt ^| findstr /C:"STATE"') do (
    set dhcpClientStatus=%%A
)

if /i "%dhcpClientStatus%" NEQ "STOPPED" (
    del "result.txt" /q
    exit /b 0
) else (
    del "result.txt" /q
    exit /b 1
)
