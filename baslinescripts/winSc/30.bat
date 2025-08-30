@echo off
netsh advfirewall show allprofiles | findstr /i "State" | findstr /i "ON"
if %errorlevel% neq 0 (
    exit /b 1
) else (
    exit /b 0
)