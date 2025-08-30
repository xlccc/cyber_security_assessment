@echo off
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" > nul 2>&1
if %errorlevel% NEQ 0 (
    exit /b 0
) else (
    exit /b 1
)