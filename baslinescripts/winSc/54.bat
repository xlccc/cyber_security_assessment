@echo off

setlocal enabledelayedexpansion
netsh interface ip show config | findstr "DNS" > result.txt
set dnsConfigured=0
for /f "tokens=*" %%h in (result.txt) do (
    echo %%h | findstr "114.114.114.114" >nul && set dnsConfigured=1
    echo %%h | findstr "114.114.114.115" >nul && set dnsConfigured=1
)
del result.txt
if !dnsConfigured! == 0 (
    exit /b 0
) else (
    exit /b 1
)
endlocal