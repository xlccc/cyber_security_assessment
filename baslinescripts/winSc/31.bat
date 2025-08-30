@echo off
for /f "tokens=3" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "PortNumber"') do set PortNumber=%%a
if PortNumber == "0xd3d" (
    exit /b 0
) else (
    exit /b 1
)